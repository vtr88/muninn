#include "muninn.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define HTTP_LINE_MAX 8192
#define HTTP_QUEUE_MAX 128

enum parser_role {
	PARSER_REQUEST,
	PARSER_RESPONSE
};

enum parser_state {
	HTTP_START_LINE,
	HTTP_HEADERS,
	HTTP_BODY_FIXED,
	HTTP_CHUNK_SIZE,
	HTTP_CHUNK_DATA,
	HTTP_CHUNK_CRLF,
	HTTP_TRAILERS,
	HTTP_BODY_UNTIL_EOF,
	HTTP_TUNNEL,
	HTTP_ERROR
};

/* Informacao minima guardada ate a resposta correspondente chegar. */
struct queued_request {
	char method[32];
	char target[1024];
	uint64_t transaction_id;
};

/*
 * Estado de uma unica mensagem. O body nao e copiado: contamos seus bytes e
 * avancamos pelo framing. Isso permite observar downloads grandes usando
 * memoria constante.
 */
struct http_message {
	char method[32];
	char target[1024];
	char version[32];
	char reason[128];
	int status;
	int content_length_seen;
	int transfer_encoding_seen;
	int transfer_chunked;
	int connection_close;
	int upgrade;
	int queued;
	uint64_t content_length;
	uint64_t body_received;
	uint64_t chunk_left;
	uint64_t transaction_id;
	size_t header_bytes;
	size_t trailer_bytes;
	size_t chunk_crlf_pos;
};

struct http_parser {
	struct http_observer *observer;
	enum parser_role role;
	enum parser_state state;
	struct http_message message;
	char line[HTTP_LINE_MAX];
	size_t line_len;
};

struct http_observer {
	int id;
	int disabled;
	int tunneled;
	int eof[2];
	struct http_parser request;
	struct http_parser response;
	struct queued_request queue[HTTP_QUEUE_MAX];
	size_t queue_start;
	size_t queue_count;
	struct http_observer_stats stats;
};

static enum side
parser_side(const struct http_parser *parser)
{
	return parser->role == PARSER_REQUEST ? SIDE_C2S : SIDE_S2C;
}

static void
message_reset(struct http_parser *parser)
{
	memset(&parser->message, 0, sizeof(parser->message));
	parser->line_len = 0;
	parser->state = HTTP_START_LINE;
}

/*
 * Um erro desativa apenas a interpretacao desta conexao. O relay continua
 * encaminhando os bytes intactos, que e a propriedade mais importante de uma
 * ferramenta somente de observacao.
 */
static void
parser_error(struct http_parser *parser, const char *reason)
{
	struct http_observer *observer;
	size_t i, index;

	observer = parser->observer;
	if (observer->disabled)
		return;
	observer->disabled = 1;
	observer->stats.parse_errors++;
	observer->request.state = HTTP_ERROR;
	observer->response.state = HTTP_ERROR;
	/*
	 * O parser inteiro e desativado depois de uma ambiguidade. Marcamos tanto
	 * as mensagens em curso quanto as requests enfileiradas, pois nenhuma delas
	 * recebera uma resposta interpretavel depois daqui.
	 */
	capture_transaction_error(observer->request.message.transaction_id);
	capture_transaction_error(observer->response.message.transaction_id);
	for (i = 0; i < observer->queue_count; i++) {
		index = (observer->queue_start + i) % HTTP_QUEUE_MAX;
		capture_transaction_error(observer->queue[index].transaction_id);
	}
	log_add(parser_side(parser), "#%d parser HTTP: %s", observer->id,
	    reason);
}

static char *
trim_value(char *value)
{
	char *end;

	while (*value != '\0' && isspace((unsigned char)*value))
		value++;
	end = value + strlen(value);
	while (end > value && isspace((unsigned char)end[-1]))
		*--end = '\0';
	return value;
}

/* Procura um token separado por virgulas sem aceitar correspondencia parcial. */
static int
header_has_token(const char *value, const char *wanted)
{
	const char *end, *start;
	size_t len;

	start = value;
	for (;;) {
		while (*start == ' ' || *start == '\t' || *start == ',')
			start++;
		end = strchr(start, ',');
		if (end == NULL)
			end = start + strlen(start);
		while (end > start && isspace((unsigned char)end[-1]))
			end--;
		len = (size_t)(end - start);
		if (strlen(wanted) == len && strncasecmp(start, wanted, len) == 0)
			return 1;
		if (*end == '\0')
			return 0;
		start = end + 1;
	}
}

/* Transfer-Encoding e definido pelo ultimo coding da lista, nao por qualquer um. */
static int
header_last_token_is(const char *value, const char *wanted)
{
	const char *end, *start;
	size_t len;

	end = value + strlen(value);
	while (end > value && isspace((unsigned char)end[-1]))
		end--;
	start = end;
	while (start > value && start[-1] != ',')
		start--;
	while (start < end && isspace((unsigned char)*start))
		start++;
	len = (size_t)(end - start);
	return len == strlen(wanted) && strncasecmp(start, wanted, len) == 0;
}

static int
parse_content_length(const char *value, uint64_t *result)
{
	char *end, *next;
	unsigned long long number;
	uint64_t first;
	int seen;

	first = 0;
	seen = 0;
	for (;;) {
		while (*value == ' ' || *value == '\t')
			value++;
		if (*value == '\0' || *value == '-')
			return -1;
		errno = 0;
		number = strtoull(value, &end, 10);
		if (errno == ERANGE || end == value)
			return -1;
		next = end;
		while (*next == ' ' || *next == '\t')
			next++;
		if (*next != '\0' && *next != ',')
			return -1;
		if (seen && first != (uint64_t)number)
			return -1;
		first = (uint64_t)number;
		seen = 1;
		if (*next == '\0')
			break;
		value = next + 1;
	}
	*result = first;
	return seen ? 0 : -1;
}

static int
queue_push(struct http_observer *observer, const struct http_message *message)
{
	struct queued_request *request;
	size_t index;

	if (observer->queue_count == HTTP_QUEUE_MAX)
		return -1;
	index = (observer->queue_start + observer->queue_count) % HTTP_QUEUE_MAX;
	request = &observer->queue[index];
	snprintf(request->method, sizeof(request->method), "%s",
	    message->method);
	snprintf(request->target, sizeof(request->target), "%s",
	    message->target);
	request->transaction_id = message->transaction_id;
	observer->queue_count++;
	return 0;
}

static struct queued_request *
queue_peek(struct http_observer *observer)
{
	if (observer->queue_count == 0)
		return NULL;
	return &observer->queue[observer->queue_start];
}

static void
queue_pop(struct http_observer *observer)
{
	if (observer->queue_count == 0)
		return;
	observer->queue_start = (observer->queue_start + 1) % HTTP_QUEUE_MAX;
	observer->queue_count--;
}

static int
response_is_informational(const struct http_message *message)
{
	return message->status >= 100 && message->status < 200 &&
	    message->status != 101;
}

static int method_is(const struct queued_request *, const char *);

/* Finaliza uma mensagem e prepara o parser para bytes keep-alive seguintes. */
static void
message_complete(struct http_parser *parser)
{
	struct http_message *message;
	struct http_observer *observer;
	struct queued_request *request;
	int becomes_tunnel;

	observer = parser->observer;
	message = &parser->message;
	if (parser->role == PARSER_REQUEST) {
		capture_request_complete(message->transaction_id);
		observer->stats.requests++;
		observer->stats.request_body_bytes += message->body_received;
		log_add(SIDE_C2S, "#%d request %s %s (%llu bytes de body)",
		    observer->id, message->method, message->target,
		    (unsigned long long)message->body_received);
	} else {
		request = queue_peek(observer);
		becomes_tunnel = message->status == 101 ||
		    (method_is(request, "CONNECT") && message->status >= 200 &&
		    message->status < 300);
		observer->stats.responses++;
		capture_response_complete(request == NULL ? 0 :
		    request->transaction_id, response_is_informational(message));
		observer->stats.response_body_bytes += message->body_received;
		if (request != NULL)
			log_add(SIDE_S2C,
			    "#%d response %d para %s %s (%llu bytes de body)",
			    observer->id, message->status, request->method,
			    request->target,
			    (unsigned long long)message->body_received);
		else
			log_add(SIDE_S2C, "#%d response %d (%llu bytes de body)",
			    observer->id, message->status,
			    (unsigned long long)message->body_received);

		if (!response_is_informational(message))
			queue_pop(observer);
		if (becomes_tunnel) {
			observer->tunneled = 1;
			observer->stats.tunneled = 1;
			observer->request.state = HTTP_TUNNEL;
			observer->response.state = HTTP_TUNNEL;
			log_add(SIDE_S2C, "#%d upgrade: trafego agora e opaco",
			    observer->id);
			return;
		}
	}
	message_reset(parser);
}

static int
parse_request_line(struct http_parser *parser, const char *line)
{
	struct http_message *message;
	char extra;
	int fields;

	message = &parser->message;
	fields = sscanf(line, "%31s %1023s %31s %c", message->method,
	    message->target, message->version, &extra);
	if (fields != 3 || strncmp(message->version, "HTTP/", 5) != 0)
		return -1;
	return 0;
}

static int
parse_response_line(struct http_parser *parser, const char *line)
{
	struct http_message *message;
	int fields;

	message = &parser->message;
	message->reason[0] = '\0';
	fields = sscanf(line, "%31s %d %127[^\r\n]", message->version,
	    &message->status, message->reason);
	if (fields < 2 || strncmp(message->version, "HTTP/", 5) != 0 ||
	    message->status < 100 || message->status > 999)
		return -1;
	return 0;
}

static int
parse_header_line(struct http_parser *parser, char *line)
{
	struct http_message *message;
	char *colon, *name, *value;
	uint64_t length;
	size_t i;

	message = &parser->message;
	if (line[0] == ' ' || line[0] == '\t')
		return -1;
	colon = strchr(line, ':');
	if (colon == NULL || colon == line)
		return -1;
	*colon = '\0';
	name = line;
	value = trim_value(colon + 1);
	for (i = 0; name[i] != '\0'; i++) {
		unsigned char c = (unsigned char)name[i];

		if (!(isalnum(c) || c == '!' || c == '#' || c == '$' ||
		    c == '%' || c == '&' || c == '\'' || c == '*' ||
		    c == '+' || c == '-' || c == '.' || c == '^' ||
		    c == '_' || c == '`' || c == '|' || c == '~'))
			return -1;
	}

	if (strcasecmp(name, "Content-Length") == 0) {
		if (parse_content_length(value, &length) == -1)
			return -1;
		if (message->content_length_seen &&
		    message->content_length != length)
			return -1;
		message->content_length_seen = 1;
		message->content_length = length;
	} else if (strcasecmp(name, "Transfer-Encoding") == 0) {
		message->transfer_encoding_seen = 1;
		message->transfer_chunked =
		    header_last_token_is(value, "chunked");
	} else if (strcasecmp(name, "Connection") == 0) {
		if (header_has_token(value, "close"))
			message->connection_close = 1;
		if (header_has_token(value, "upgrade"))
			message->upgrade = 1;
	} else if (strcasecmp(name, "Upgrade") == 0 && *value != '\0') {
		message->upgrade = 1;
	}
	return 0;
}

static int
method_is(const struct queued_request *request, const char *method)
{
	return request != NULL && strcasecmp(request->method, method) == 0;
}

/* Decide o framing do body assim que a linha vazia encerra os headers. */
static void
headers_complete(struct http_parser *parser)
{
	struct http_message *message;
	struct http_observer *observer;
	struct queued_request *request;
	int no_body;

	observer = parser->observer;
	message = &parser->message;
	if (parser->role == PARSER_REQUEST) {
		if (!message->queued) {
			if (queue_push(observer, message) == -1) {
				parser_error(parser, "fila de requests excedida");
				return;
			}
			message->queued = 1;
		}

		/* O preambulo PRI pertence ao HTTP/2, que permanece opaco na v1. */
		if (strcmp(message->method, "PRI") == 0 &&
		    strcmp(message->version, "HTTP/2.0") == 0) {
			observer->tunneled = 1;
			observer->stats.tunneled = 1;
			observer->request.state = HTTP_TUNNEL;
			observer->response.state = HTTP_TUNNEL;
			log_add(SIDE_C2S, "#%d HTTP/2 detectado; trafego opaco",
			    observer->id);
			return;
		}
		if (message->transfer_encoding_seen &&
		    !message->transfer_chunked) {
			parser_error(parser,
			    "Transfer-Encoding de request termina sem chunked");
			return;
		}
		if (message->transfer_chunked)
			parser->state = HTTP_CHUNK_SIZE;
		else if (message->content_length_seen &&
		    message->content_length > 0)
			parser->state = HTTP_BODY_FIXED;
		else
			message_complete(parser);
		return;
	}

	request = queue_peek(observer);
	no_body = (message->status >= 100 && message->status < 200) ||
	    message->status == 204 || message->status == 205 ||
	    message->status == 304 || method_is(request, "HEAD") ||
	    (method_is(request, "CONNECT") && message->status >= 200 &&
	    message->status < 300);
	if (no_body) {
		message_complete(parser);
	} else if (message->transfer_chunked) {
		parser->state = HTTP_CHUNK_SIZE;
	} else if (message->content_length_seen) {
		if (message->content_length == 0)
			message_complete(parser);
		else
			parser->state = HTTP_BODY_FIXED;
	} else {
		/* Sem framing explicito, a resposta termina quando o socket fecha. */
		parser->state = HTTP_BODY_UNTIL_EOF;
	}
}

static int
parse_chunk_size(struct http_parser *parser, char *line)
{
	char *end, *extension, *value;
	unsigned long long size;

	extension = strchr(line, ';');
	if (extension != NULL)
		*extension = '\0';
	value = trim_value(line);
	if (*value == '\0' || *value == '-')
		return -1;
	errno = 0;
	size = strtoull(value, &end, 16);
	while (*end != '\0' && isspace((unsigned char)*end))
		end++;
	if (errno == ERANGE || *end != '\0')
		return -1;
	parser->message.chunk_left = (uint64_t)size;
	parser->message.chunk_crlf_pos = 0;
	parser->state = size == 0 ? HTTP_TRAILERS : HTTP_CHUNK_DATA;
	return 0;
}

static void
process_line(struct http_parser *parser)
{
	char *line;

	line = parser->line;
	if (parser->line_len > 0 && line[parser->line_len - 1] == '\r')
		line[--parser->line_len] = '\0';
	else
		line[parser->line_len] = '\0';

	switch (parser->state) {
	case HTTP_START_LINE:
		if (parser->line_len == 0)
			break;
		if ((parser->role == PARSER_REQUEST &&
		    parse_request_line(parser, line) == -1) ||
		    (parser->role == PARSER_RESPONSE &&
		    parse_response_line(parser, line) == -1)) {
			parser_error(parser, "start-line invalida");
			break;
		}
		if (parser->role == PARSER_REQUEST) {
			parser->message.transaction_id = capture_request_begin(
			    parser->observer->id, parser->message.method,
			    parser->message.target, parser->message.version);
		} else {
			struct queued_request *request;

			request = queue_peek(parser->observer);
			parser->message.transaction_id = request == NULL ? 0 :
			    request->transaction_id;
			capture_response_begin(parser->message.transaction_id,
			    parser->message.version, parser->message.status,
			    parser->message.reason);
		}
		parser->state = HTTP_HEADERS;
		break;
	case HTTP_HEADERS:
		if (parser->line_len == 0) {
			capture_headers_complete(parser->message.transaction_id,
			    parser->role == PARSER_RESPONSE);
			headers_complete(parser);
		} else {
			/* A captura ocorre antes de parse_header_line inserir um NUL. */
			capture_header(parser->message.transaction_id,
			    parser->role == PARSER_RESPONSE, line);
			if (parse_header_line(parser, line) == -1)
			parser_error(parser, "header invalido ou ambiguo");
		}
		break;
	case HTTP_CHUNK_SIZE:
		if (parse_chunk_size(parser, line) == -1)
			parser_error(parser, "tamanho de chunk invalido");
		break;
	case HTTP_TRAILERS:
		if (parser->line_len == 0)
			message_complete(parser);
		else if (strchr(line, ':') == NULL)
			parser_error(parser, "trailer invalido");
		break;
	default:
		parser_error(parser, "linha em estado inesperado");
		break;
	}
	parser->line_len = 0;
}

static int
state_reads_lines(enum parser_state state)
{
	return state == HTTP_START_LINE || state == HTTP_HEADERS ||
	    state == HTTP_CHUNK_SIZE || state == HTTP_TRAILERS;
}

static void
parser_feed(struct http_parser *parser, const unsigned char *buf, size_t len)
{
	struct http_message *message;
	uint64_t remaining;
	size_t pos, take;
	unsigned char byte;

	pos = 0;
	while (pos < len && !parser->observer->disabled &&
	    !parser->observer->tunneled) {
		message = &parser->message;
		if (state_reads_lines(parser->state)) {
			byte = buf[pos++];
			if (byte == '\0') {
				parser_error(parser, "byte NUL em linha HTTP");
				continue;
			}
			if (parser->state == HTTP_START_LINE ||
			    parser->state == HTTP_HEADERS) {
				message->header_bytes++;
				if (message->header_bytes > HEADER_MAX) {
					parser_error(parser, "headers excedem o limite");
					continue;
				}
			}
			if (parser->state == HTTP_TRAILERS) {
				message->trailer_bytes++;
				if (message->trailer_bytes > HEADER_MAX) {
					parser_error(parser,
					    "trailers excedem o limite");
					continue;
				}
			}
			if (byte == '\n') {
				process_line(parser);
				continue;
			}
			if (parser->line_len + 1 >= sizeof(parser->line)) {
				parser_error(parser, "linha HTTP excede o limite");
				continue;
			}
			parser->line[parser->line_len++] = (char)byte;
			continue;
		}

		switch (parser->state) {
		case HTTP_BODY_FIXED:
			remaining = message->content_length - message->body_received;
			take = len - pos;
			if ((uint64_t)take > remaining)
				take = (size_t)remaining;
			capture_body(message->transaction_id,
			    parser->role == PARSER_RESPONSE, buf + pos, take);
			message->body_received += take;
			pos += take;
			if (message->body_received == message->content_length)
				message_complete(parser);
			break;
		case HTTP_CHUNK_DATA:
			take = len - pos;
			if ((uint64_t)take > message->chunk_left)
				take = (size_t)message->chunk_left;
			if (UINT64_MAX - message->body_received < take) {
				parser_error(parser, "body excede contador de 64 bits");
				break;
			}
			capture_body(message->transaction_id,
			    parser->role == PARSER_RESPONSE, buf + pos, take);
			message->body_received += take;
			message->chunk_left -= take;
			pos += take;
			if (message->chunk_left == 0)
				parser->state = HTTP_CHUNK_CRLF;
			break;
		case HTTP_CHUNK_CRLF:
			byte = buf[pos++];
			if (message->chunk_crlf_pos == 0 && byte == '\r')
				message->chunk_crlf_pos = 1;
			else if ((message->chunk_crlf_pos == 0 ||
			    message->chunk_crlf_pos == 1) && byte == '\n') {
				message->chunk_crlf_pos = 0;
				parser->state = HTTP_CHUNK_SIZE;
			} else
				parser_error(parser, "fim de chunk invalido");
			break;
		case HTTP_BODY_UNTIL_EOF:
			if (UINT64_MAX - message->body_received < len - pos) {
				parser_error(parser, "body excede contador de 64 bits");
				break;
			}
			capture_body(message->transaction_id,
			    parser->role == PARSER_RESPONSE, buf + pos, len - pos);
			message->body_received += len - pos;
			pos = len;
			break;
		case HTTP_TUNNEL:
		case HTTP_ERROR:
			return;
		default:
			parser_error(parser, "estado HTTP invalido");
			break;
		}
	}
}

struct http_observer *
http_observer_new(int id)
{
	struct http_observer *observer;

	observer = calloc(1, sizeof(*observer));
	if (observer == NULL)
		return NULL;
	observer->id = id;
	observer->request.observer = observer;
	observer->request.role = PARSER_REQUEST;
	observer->response.observer = observer;
	observer->response.role = PARSER_RESPONSE;
	message_reset(&observer->request);
	message_reset(&observer->response);
	return observer;
}

void
http_observer_feed(struct http_observer *observer, enum side side,
    const unsigned char *buf, size_t len)
{
	if (observer == NULL || buf == NULL || len == 0 || observer->disabled ||
	    observer->tunneled || observer->eof[side])
		return;
	parser_feed(side == SIDE_C2S ? &observer->request :
	    &observer->response, buf, len);
}

void
http_observer_eof(struct http_observer *observer, enum side side)
{
	struct http_parser *parser;

	if (observer == NULL || observer->eof[side])
		return;
	observer->eof[side] = 1;
	if (observer->disabled || observer->tunneled)
		return;
	parser = side == SIDE_C2S ? &observer->request : &observer->response;
	if (parser->state == HTTP_BODY_UNTIL_EOF)
		message_complete(parser);
	else if (parser->state != HTTP_START_LINE || parser->line_len != 0)
		parser_error(parser, "EOF no meio de uma mensagem");
}

void
http_observer_get_stats(const struct http_observer *observer,
    struct http_observer_stats *stats)
{
	if (stats == NULL)
		return;
	memset(stats, 0, sizeof(*stats));
	if (observer != NULL)
		*stats = observer->stats;
}

void
http_observer_free(struct http_observer *observer)
{
	free(observer);
}
