#include "capture.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/*
 * O capture store e deliberadamente simples: existe uma unica instancia no
 * processo e um unico mutex protege toda a sua estrutura. O caminho de rede
 * apenas faz copias curtas; a Parte 6 podera tirar snapshots sem receber
 * ponteiros para memoria que uma thread de conexao ainda esteja alterando.
 */
struct stored_message {
	char *start_line;
	char *headers;
	unsigned char *body;
	size_t headers_len;
	size_t body_len;
	uint64_t body_total;
	char content_type[128];
	char content_encoding[64];
	int headers_truncated;
	int body_truncated;
	int binary;
};

struct stored_connection {
	struct capture_connection_view view;
	long long started_monotonic_ms;
	struct stored_connection *next;
};

struct stored_transaction {
	struct capture_transaction_summary summary;
	long long started_monotonic_ms;
	struct stored_message request;
	struct stored_message response;
	struct stored_transaction *prev;
	struct stored_transaction *next;
};

struct capture_store {
	pthread_mutex_t lock;
	int initialized;
	struct capture_limits limits;
	size_t memory_used;
	size_t connection_count;
	size_t transaction_count;
	uint64_t next_transaction_id;
	struct stored_connection *connections;
	struct stored_transaction *transactions_head;
	struct stored_transaction *transactions_tail;
};

static struct capture_store store = {
	.lock = PTHREAD_MUTEX_INITIALIZER
};

/* Tempo civil serve para exibir quando algo ocorreu; monotonic mede duracao. */
static long long
wallclock_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		return 0;
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static long long
monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		return 0;
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int
transaction_terminal(enum capture_transaction_state state)
{
	return state == CAPTURE_COMPLETE || state == CAPTURE_INTERRUPTED ||
	    state == CAPTURE_ERROR;
}

static struct stored_connection *
find_connection_locked(int id)
{
	struct stored_connection *connection;

	for (connection = store.connections; connection != NULL;
	    connection = connection->next) {
		if (connection->view.id == id)
			return connection;
	}
	return NULL;
}

static struct stored_transaction *
find_transaction_locked(uint64_t id)
{
	struct stored_transaction *transaction;

	for (transaction = store.transactions_head; transaction != NULL;
	    transaction = transaction->next) {
		if (transaction->summary.id == id)
			return transaction;
	}
	return NULL;
}

/* Todo byte dinamico entra e sai pelo mesmo contador. */
static void
free_message_locked(struct stored_message *message)
{
	if (message->start_line != NULL) {
		store.memory_used -= strlen(message->start_line) + 1;
		free(message->start_line);
	}
	if (message->headers != NULL) {
		store.memory_used -= message->headers_len + 1;
		free(message->headers);
	}
	if (message->body != NULL) {
		store.memory_used -= message->body_len;
		free(message->body);
	}
	memset(message, 0, sizeof(*message));
}

static void
unlink_transaction_locked(struct stored_transaction *transaction)
{
	if (transaction->prev != NULL)
		transaction->prev->next = transaction->next;
	else
		store.transactions_head = transaction->next;
	if (transaction->next != NULL)
		transaction->next->prev = transaction->prev;
	else
		store.transactions_tail = transaction->prev;
	free_message_locked(&transaction->request);
	free_message_locked(&transaction->response);
	free(transaction);
	store.transaction_count--;
}

/*
 * Somente registros terminais podem sair. Uma request ativa nunca desaparece
 * enquanto o parser ainda conserva seu ID.
 */
static int
evict_oldest_terminal_locked(void)
{
	struct stored_transaction *transaction;

	for (transaction = store.transactions_head; transaction != NULL;
	    transaction = transaction->next) {
		if (transaction_terminal(transaction->summary.state)) {
			unlink_transaction_locked(transaction);
			return 1;
		}
	}
	return 0;
}

static void
remove_connection_locked(struct stored_connection *wanted)
{
	struct stored_connection **cursor;
	struct stored_transaction *next, *transaction;

	/* Uma transacao nao deve sobreviver sem os metadados da sua conexao. */
	for (transaction = store.transactions_head; transaction != NULL;
	    transaction = next) {
		next = transaction->next;
		if (transaction->summary.connection_id == wanted->view.id)
			unlink_transaction_locked(transaction);
	}

	for (cursor = &store.connections; *cursor != NULL;
	    cursor = &(*cursor)->next) {
		if (*cursor == wanted) {
			*cursor = wanted->next;
			free(wanted);
			store.connection_count--;
			return;
		}
	}
}

static int
evict_oldest_closed_connection_locked(void)
{
	struct stored_connection *connection, *oldest;

	oldest = NULL;
	for (connection = store.connections; connection != NULL;
	    connection = connection->next) {
		if (!connection->view.active && (oldest == NULL ||
		    connection->view.started_unix_ms <
		    oldest->view.started_unix_ms))
			oldest = connection;
	}
	if (oldest == NULL)
		return 0;
	remove_connection_locked(oldest);
	return 1;
}

/*
 * Tenta abrir espaco descartando historico terminal. O retorno pode ser menor
 * que wanted: nesse caso o chamador armazena o prefixo possivel e marca o
 * campo como truncado.
 */
static size_t
available_bytes_locked(size_t wanted)
{
	size_t available;

	while (store.memory_used > store.limits.global_bytes ||
	    wanted > store.limits.global_bytes - store.memory_used) {
		if (!evict_oldest_terminal_locked())
			break;
	}
	available = store.limits.global_bytes - store.memory_used;
	return wanted < available ? wanted : available;
}

static void
copy_text(char *destination, size_t size, const char *source)
{
	if (source == NULL)
		source = "";
	(void)snprintf(destination, size, "%s", source);
}

/* strdup nao faz parte do C99 puro; esta versao evita depender dessa extensao. */
static char *
duplicate_text(const char *source)
{
	char *copy;
	size_t length;

	length = strlen(source) + 1;
	copy = malloc(length);
	if (copy != NULL)
		memcpy(copy, source, length);
	return copy;
}

/* Substitui uma start-line contabilizando inclusive seu terminador NUL. */
static int
set_start_line_locked(struct stored_message *message, const char *line)
{
	char *copy;
	size_t allowed, length;

	if (line == NULL)
		line = "";
	if (message->start_line != NULL) {
		store.memory_used -= strlen(message->start_line) + 1;
		free(message->start_line);
		message->start_line = NULL;
	}
	length = strlen(line);
	allowed = store.limits.header_bytes;
	if (allowed > length)
		allowed = length;
	if (allowed < length)
		message->headers_truncated = 1;

	/* Um byte adicional e necessario para o terminador da string. */
	allowed = available_bytes_locked(allowed + 1);
	if (allowed == 0) {
		message->headers_truncated = 1;
		return -1;
	}
	copy = malloc(allowed);
	if (copy == NULL) {
		message->headers_truncated = 1;
		return -1;
	}
	if (allowed - 1 < length)
		message->headers_truncated = 1;
	memcpy(copy, line, allowed - 1);
	copy[allowed - 1] = '\0';
	message->start_line = copy;
	store.memory_used += allowed;
	return 0;
}

/* Extrai metadados de representacao sem modificar a linha usada pelo parser. */
static void
remember_content_metadata(struct stored_message *message, const char *line)
{
	const char *colon, *end, *value;
	char *destination;
	size_t destination_size;
	size_t name_len, value_len;

	colon = strchr(line, ':');
	if (colon == NULL)
		return;
	name_len = (size_t)(colon - line);
	if (name_len == strlen("Content-Type") &&
	    strncasecmp(line, "Content-Type", name_len) == 0) {
		destination = message->content_type;
		destination_size = sizeof(message->content_type);
	} else if (name_len == strlen("Content-Encoding") &&
	    strncasecmp(line, "Content-Encoding", name_len) == 0) {
		destination = message->content_encoding;
		destination_size = sizeof(message->content_encoding);
	} else {
		return;
	}
	value = colon + 1;
	while (*value == ' ' || *value == '\t')
		value++;
	end = value + strlen(value);
	while (end > value && isspace((unsigned char)end[-1]))
		end--;
	value_len = (size_t)(end - value);
	if (value_len >= destination_size)
		value_len = destination_size - 1;
	memcpy(destination, value, value_len);
	destination[value_len] = '\0';
}

static void
append_header_locked(struct stored_message *message, const char *line)
{
	char *resized;
	size_t allowed, line_len, limit_left, wanted;

	line_len = strlen(line);
	wanted = line_len + 2; /* CRLF removido pelo parser e restaurado aqui. */
	limit_left = store.limits.header_bytes;
	if (message->start_line != NULL) {
		size_t start_len = strlen(message->start_line);

		limit_left = start_len < limit_left ? limit_left - start_len : 0;
	}
	limit_left = message->headers_len < limit_left ?
	    limit_left - message->headers_len : 0;
	allowed = wanted < limit_left ? wanted : limit_left;
	allowed = available_bytes_locked(allowed + (message->headers == NULL));
	if (message->headers == NULL && allowed > 0)
		allowed--;
	if (allowed < wanted)
		message->headers_truncated = 1;
	if (allowed == 0)
		return;

	resized = realloc(message->headers, message->headers_len + allowed + 1);
	if (resized == NULL) {
		message->headers_truncated = 1;
		return;
	}
	message->headers = resized;
	if (allowed <= line_len) {
		memcpy(message->headers + message->headers_len, line, allowed);
	} else {
		memcpy(message->headers + message->headers_len, line, line_len);
		message->headers[message->headers_len + line_len] = '\r';
		if (allowed > line_len + 1)
			message->headers[message->headers_len + line_len + 1] = '\n';
	}
	message->headers_len += allowed;
	message->headers[message->headers_len] = '\0';
	store.memory_used += allowed + (message->headers_len == allowed);
}

static int
body_byte_is_binary(unsigned char byte)
{
	return byte == 0 || (byte < 0x20 && byte != '\t' && byte != '\n' &&
	    byte != '\r') || byte == 0x7f;
}

static void
append_body_locked(struct stored_message *message,
	const unsigned char *data, size_t length)
{
	unsigned char *resized;
	size_t allowed, i, limit_left;

	if (UINT64_MAX - message->body_total < length)
		message->body_total = UINT64_MAX;
	else
		message->body_total += length;
	for (i = 0; i < length; i++) {
		if (body_byte_is_binary(data[i])) {
			message->binary = 1;
			break;
		}
	}
	limit_left = message->body_len < store.limits.body_bytes ?
	    store.limits.body_bytes - message->body_len : 0;
	allowed = length < limit_left ? length : limit_left;
	allowed = available_bytes_locked(allowed);
	if (allowed < length)
		message->body_truncated = 1;
	if (allowed == 0)
		return;
	resized = realloc(message->body, message->body_len + allowed);
	if (resized == NULL) {
		message->body_truncated = 1;
		return;
	}
	message->body = resized;
	memcpy(message->body + message->body_len, data, allowed);
	message->body_len += allowed;
	store.memory_used += allowed;
}

int
capture_init(const struct capture_limits *limits)
{
	struct capture_limits defaults;

	capture_cleanup();
	defaults.global_bytes = CAPTURE_DEFAULT_GLOBAL_BYTES;
	defaults.body_bytes = CAPTURE_DEFAULT_BODY_BYTES;
	defaults.header_bytes = CAPTURE_DEFAULT_HEADER_BYTES;
	defaults.max_transactions = CAPTURE_DEFAULT_TRANSACTIONS;
	defaults.max_connections = CAPTURE_DEFAULT_CONNECTIONS;
	if (limits != NULL)
		defaults = *limits;
	if (defaults.global_bytes == 0 || defaults.body_bytes == 0 ||
	    defaults.header_bytes == 0 || defaults.max_transactions == 0 ||
	    defaults.max_connections == 0)
		return -1;

	pthread_mutex_lock(&store.lock);
	store.limits = defaults;
	store.next_transaction_id = 1;
	store.initialized = 1;
	pthread_mutex_unlock(&store.lock);
	return 0;
}

void
capture_cleanup(void)
{
	struct stored_connection *connection, *next_connection;
	struct stored_transaction *next_transaction, *transaction;

	pthread_mutex_lock(&store.lock);
	for (transaction = store.transactions_head; transaction != NULL;
	    transaction = next_transaction) {
		next_transaction = transaction->next;
		free_message_locked(&transaction->request);
		free_message_locked(&transaction->response);
		free(transaction);
	}
	for (connection = store.connections; connection != NULL;
	    connection = next_connection) {
		next_connection = connection->next;
		free(connection);
	}
	store.initialized = 0;
	store.memory_used = 0;
	store.connection_count = 0;
	store.transaction_count = 0;
	store.next_transaction_id = 1;
	store.connections = NULL;
	store.transactions_head = NULL;
	store.transactions_tail = NULL;
	pthread_mutex_unlock(&store.lock);
}

int
capture_connection_open(int id, const char *client_host,
	const char *client_port)
{
	struct stored_connection *connection;

	connection = calloc(1, sizeof(*connection));
	if (connection == NULL)
		return -1;
	connection->view.id = id;
	connection->view.started_unix_ms = wallclock_ms();
	connection->started_monotonic_ms = monotonic_ms();
	connection->view.active = 1;
	connection->view.upstream_tls.verified = -2;
	connection->view.browser_tls.verified = -2;
	copy_text(connection->view.client_host,
	    sizeof(connection->view.client_host), client_host);
	copy_text(connection->view.client_port,
	    sizeof(connection->view.client_port), client_port);

	pthread_mutex_lock(&store.lock);
	if (!store.initialized || find_connection_locked(id) != NULL) {
		pthread_mutex_unlock(&store.lock);
		free(connection);
		return -1;
	}
	while (store.connection_count >= store.limits.max_connections) {
		if (!evict_oldest_closed_connection_locked()) {
			pthread_mutex_unlock(&store.lock);
			free(connection);
			return -1;
		}
	}
	connection->next = store.connections;
	store.connections = connection;
	store.connection_count++;
	pthread_mutex_unlock(&store.lock);
	return 0;
}

void
capture_connection_target(int id, const char *host, const char *port,
	int is_tls, int passthrough)
{
	struct stored_connection *connection;

	pthread_mutex_lock(&store.lock);
	connection = store.initialized ? find_connection_locked(id) : NULL;
	if (connection != NULL) {
		copy_text(connection->view.target_host,
		    sizeof(connection->view.target_host), host);
		copy_text(connection->view.target_port,
		    sizeof(connection->view.target_port), port);
		connection->view.is_tls = is_tls;
		connection->view.passthrough = passthrough;
	}
	pthread_mutex_unlock(&store.lock);
}

void
capture_connection_tls(int id, int upstream, const char *version,
	const char *cipher, const char *alpn, int verified)
{
	struct capture_tls_view *tls;
	struct stored_connection *connection;

	pthread_mutex_lock(&store.lock);
	connection = store.initialized ? find_connection_locked(id) : NULL;
	if (connection != NULL) {
		tls = upstream ? &connection->view.upstream_tls :
		    &connection->view.browser_tls;
		tls->present = 1;
		tls->verified = verified;
		copy_text(tls->version, sizeof(tls->version), version);
		copy_text(tls->cipher, sizeof(tls->cipher), cipher);
		copy_text(tls->alpn, sizeof(tls->alpn), alpn);
	}
	pthread_mutex_unlock(&store.lock);
}

void
capture_connection_close(int id)
{
	struct stored_connection *connection;
	struct stored_transaction *transaction;
	long long now;

	now = monotonic_ms();
	pthread_mutex_lock(&store.lock);
	connection = store.initialized ? find_connection_locked(id) : NULL;
	if (connection != NULL) {
		connection->view.active = 0;
		connection->view.duration_ms = now -
		    connection->started_monotonic_ms;
	}
	for (transaction = store.transactions_head; transaction != NULL;
	    transaction = transaction->next) {
		if (transaction->summary.connection_id == id &&
		    !transaction_terminal(transaction->summary.state)) {
			transaction->summary.state = CAPTURE_INTERRUPTED;
			transaction->summary.duration_ms = now -
			    transaction->started_monotonic_ms;
		}
	}
	pthread_mutex_unlock(&store.lock);
}

uint64_t
capture_request_begin(int connection_id, const char *method,
	const char *target, const char *version)
{
	struct stored_connection *connection;
	struct stored_transaction *transaction;
	char line[1400];

	if (method == NULL)
		method = "";
	if (target == NULL)
		target = "";
	if (version == NULL)
		version = "";
	transaction = calloc(1, sizeof(*transaction));
	if (transaction == NULL)
		return 0;
	transaction->summary.connection_id = connection_id;
	transaction->summary.state = CAPTURE_REQUEST;
	transaction->summary.started_unix_ms = wallclock_ms();
	transaction->started_monotonic_ms = monotonic_ms();
	copy_text(transaction->summary.method,
	    sizeof(transaction->summary.method), method);
	copy_text(transaction->summary.target,
	    sizeof(transaction->summary.target), target);
	(void)snprintf(line, sizeof(line), "%s %s %s", method, target, version);

	pthread_mutex_lock(&store.lock);
	connection = store.initialized ? find_connection_locked(connection_id) :
	    NULL;
	if (connection == NULL) {
		pthread_mutex_unlock(&store.lock);
		free(transaction);
		return 0;
	}
	while (store.transaction_count >= store.limits.max_transactions) {
		if (!evict_oldest_terminal_locked()) {
			pthread_mutex_unlock(&store.lock);
			free(transaction);
			return 0;
		}
	}
	transaction->summary.id = store.next_transaction_id++;
	copy_text(transaction->summary.host,
	    sizeof(transaction->summary.host), connection->view.target_host);
	if (store.next_transaction_id == 0)
		store.next_transaction_id = 1;
	transaction->prev = store.transactions_tail;
	if (store.transactions_tail != NULL)
		store.transactions_tail->next = transaction;
	else
		store.transactions_head = transaction;
	store.transactions_tail = transaction;
	store.transaction_count++;
	(void)set_start_line_locked(&transaction->request, line);
	pthread_mutex_unlock(&store.lock);
	return transaction->summary.id;
}

void
capture_response_begin(uint64_t id, const char *version, int status,
	const char *reason)
{
	struct stored_transaction *transaction;
	char line[256];

	if (id == 0)
		return;
	if (version == NULL)
		version = "";
	if (reason != NULL && *reason != '\0')
		(void)snprintf(line, sizeof(line), "%s %d %s", version, status,
		    reason);
	else
		(void)snprintf(line, sizeof(line), "%s %d", version, status);
	pthread_mutex_lock(&store.lock);
	transaction = store.initialized ? find_transaction_locked(id) : NULL;
	if (transaction != NULL) {
		/* Uma resposta final substitui o registro provisoria 1xx anterior. */
		free_message_locked(&transaction->response);
		transaction->summary.status = status;
		transaction->summary.state = CAPTURE_RESPONSE;
		(void)set_start_line_locked(&transaction->response, line);
	}
	pthread_mutex_unlock(&store.lock);
}

void
capture_header(uint64_t id, int response, const char *line)
{
	struct stored_message *message;
	struct stored_transaction *transaction;

	if (id == 0 || line == NULL)
		return;
	pthread_mutex_lock(&store.lock);
	transaction = store.initialized ? find_transaction_locked(id) : NULL;
	if (transaction != NULL) {
		message = response ? &transaction->response :
		    &transaction->request;
		remember_content_metadata(message, line);
		append_header_locked(message, line);
	}
	pthread_mutex_unlock(&store.lock);
}

void
capture_headers_complete(uint64_t id, int response)
{
	/* A linha vazia preserva a separacao visual entre headers e body. */
	capture_header(id, response, "");
}

void
capture_body(uint64_t id, int response, const unsigned char *data,
	size_t length)
{
	struct stored_message *message;
	struct stored_transaction *transaction;

	if (id == 0 || data == NULL || length == 0)
		return;
	pthread_mutex_lock(&store.lock);
	transaction = store.initialized ? find_transaction_locked(id) : NULL;
	if (transaction != NULL) {
		message = response ? &transaction->response :
		    &transaction->request;
		append_body_locked(message, data, length);
		transaction->summary.request_body_total =
		    transaction->request.body_total;
		transaction->summary.response_body_total =
		    transaction->response.body_total;
		transaction->summary.request_body_stored =
		    transaction->request.body_len;
		transaction->summary.response_body_stored =
		    transaction->response.body_len;
		transaction->summary.request_truncated =
		    transaction->request.body_truncated;
		transaction->summary.response_truncated =
		    transaction->response.body_truncated;
	}
	pthread_mutex_unlock(&store.lock);
}

void
capture_request_complete(uint64_t id)
{
	struct stored_transaction *transaction;

	pthread_mutex_lock(&store.lock);
	transaction = store.initialized ? find_transaction_locked(id) : NULL;
	if (transaction != NULL && transaction->summary.state == CAPTURE_REQUEST)
		transaction->summary.state = CAPTURE_WAITING_RESPONSE;
	pthread_mutex_unlock(&store.lock);
}

void
capture_response_complete(uint64_t id, int informational)
{
	struct stored_transaction *transaction;
	long long now;

	now = monotonic_ms();
	pthread_mutex_lock(&store.lock);
	transaction = store.initialized ? find_transaction_locked(id) : NULL;
	if (transaction != NULL) {
		if (informational) {
			transaction->summary.state = CAPTURE_WAITING_RESPONSE;
		} else {
			transaction->summary.state = CAPTURE_COMPLETE;
			transaction->summary.duration_ms = now -
			    transaction->started_monotonic_ms;
		}
	}
	pthread_mutex_unlock(&store.lock);
}

void
capture_transaction_error(uint64_t id)
{
	struct stored_transaction *transaction;
	long long now;

	now = monotonic_ms();
	pthread_mutex_lock(&store.lock);
	transaction = store.initialized ? find_transaction_locked(id) : NULL;
	if (transaction != NULL &&
	    !transaction_terminal(transaction->summary.state)) {
		transaction->summary.state = CAPTURE_ERROR;
		transaction->summary.duration_ms = now -
		    transaction->started_monotonic_ms;
	}
	pthread_mutex_unlock(&store.lock);
}

int
capture_list_connections(struct capture_connection_view **result,
	size_t *count)
{
	struct capture_connection_view *views;
	struct stored_connection *connection;
	size_t index;

	if (result == NULL || count == NULL)
		return -1;
	*result = NULL;
	*count = 0;
	pthread_mutex_lock(&store.lock);
	if (!store.initialized || store.connection_count == 0) {
		pthread_mutex_unlock(&store.lock);
		return 0;
	}
	views = calloc(store.connection_count, sizeof(*views));
	if (views == NULL) {
		pthread_mutex_unlock(&store.lock);
		return -1;
	}
	index = 0;
	for (connection = store.connections; connection != NULL;
	    connection = connection->next)
		views[index++] = connection->view;
	pthread_mutex_unlock(&store.lock);
	*result = views;
	*count = index;
	return 0;
}

static int
buffer_contains_case(const unsigned char *buffer, size_t length,
	const char *wanted)
{
	size_t i, j, wanted_length;

	if (wanted == NULL || *wanted == '\0')
		return 1;
	wanted_length = strlen(wanted);
	if (wanted_length > length)
		return 0;
	for (i = 0; i + wanted_length <= length; i++) {
		for (j = 0; j < wanted_length; j++) {
			if (tolower(buffer[i + j]) !=
			    tolower((unsigned char)wanted[j]))
				break;
		}
		if (j == wanted_length)
			return 1;
	}
	return 0;
}

static int
text_contains_case(const char *text, const char *wanted)
{
	return text != NULL && buffer_contains_case((const unsigned char *)text,
	    strlen(text), wanted);
}

static int
state_matches(enum capture_transaction_state state, const char *wanted)
{
	static const char *names[][3] = {
		{ "request", "requisicao", NULL },
		{ "waiting", "aguardando", NULL },
		{ "response", "resposta", NULL },
		{ "complete", "completa", NULL },
		{ "interrupted", "interrompida", NULL },
		{ "error", "erro", NULL }
	};
	size_t i;

	if ((size_t)state >= sizeof(names) / sizeof(names[0]))
		return 0;
	for (i = 0; names[state][i] != NULL; i++) {
		if (strcasecmp(names[state][i], wanted) == 0)
			return 1;
	}
	return 0;
}

static int
message_contains(const struct stored_message *message, const char *wanted)
{
	return text_contains_case(message->start_line, wanted) ||
	    text_contains_case(message->headers, wanted) ||
	    text_contains_case(message->content_type, wanted) ||
	    (message->body != NULL && buffer_contains_case(message->body,
	    message->body_len, wanted));
}

static int
transaction_matches_term(const struct stored_transaction *transaction,
	const char *term)
{
	char status[16];
	const char *value;

	if (strncasecmp(term, "method:", 7) == 0) {
		value = term + 7;
		return *value != '\0' &&
		    strcasecmp(transaction->summary.method, value) == 0;
	}
	if (strncasecmp(term, "host:", 5) == 0) {
		value = term + 5;
		return *value != '\0' &&
		    text_contains_case(transaction->summary.host, value);
	}
	if (strncasecmp(term, "status:", 7) == 0) {
		value = term + 7;
		(void)snprintf(status, sizeof(status), "%d",
		    transaction->summary.status);
		return *value != '\0' && strcmp(status, value) == 0;
	}
	if (strncasecmp(term, "state:", 6) == 0) {
		value = term + 6;
		return *value != '\0' &&
		    state_matches(transaction->summary.state, value);
	}
	(void)snprintf(status, sizeof(status), "%d",
	    transaction->summary.status);
	return text_contains_case(transaction->summary.method, term) ||
	    text_contains_case(transaction->summary.host, term) ||
	    text_contains_case(transaction->summary.target, term) ||
	    text_contains_case(status, term) ||
	    message_contains(&transaction->request, term) ||
	    message_contains(&transaction->response, term);
}

/* Termos separados por espaco possuem semantica AND. */
static int
transaction_matches(const struct stored_transaction *transaction,
	const char *query)
{
	char copy[256], *cursor, *save, *term;

	if (query == NULL || *query == '\0')
		return 1;
	copy_text(copy, sizeof(copy), query);
	cursor = copy;
	save = NULL;
	while ((term = strtok_r(cursor, " \t", &save)) != NULL) {
		cursor = NULL;
		if (!transaction_matches_term(transaction, term))
			return 0;
	}
	return 1;
}

int
capture_list_transactions_matching(const char *query,
	struct capture_transaction_summary **result, size_t *count)
{
	struct capture_transaction_summary *views;
	struct stored_transaction *transaction;
	size_t index, matches;

	if (result == NULL || count == NULL)
		return -1;
	*result = NULL;
	*count = 0;
	pthread_mutex_lock(&store.lock);
	if (!store.initialized || store.transaction_count == 0) {
		pthread_mutex_unlock(&store.lock);
		return 0;
	}
	matches = 0;
	for (transaction = store.transactions_head; transaction != NULL;
	    transaction = transaction->next) {
		if (transaction_matches(transaction, query))
			matches++;
	}
	if (matches == 0) {
		pthread_mutex_unlock(&store.lock);
		return 0;
	}
	views = calloc(matches, sizeof(*views));
	if (views == NULL) {
		pthread_mutex_unlock(&store.lock);
		return -1;
	}
	index = 0;
	for (transaction = store.transactions_head; transaction != NULL;
	    transaction = transaction->next) {
		if (transaction_matches(transaction, query))
			views[index++] = transaction->summary;
	}
	pthread_mutex_unlock(&store.lock);
	*result = views;
	*count = index;
	return 0;
}

int
capture_list_transactions(struct capture_transaction_summary **result,
	size_t *count)
{
	return capture_list_transactions_matching(NULL, result, count);
}

size_t
capture_clear(void)
{
	struct stored_transaction *next, *transaction;
	size_t removed;

	removed = 0;
	pthread_mutex_lock(&store.lock);
	if (store.initialized) {
		for (transaction = store.transactions_head; transaction != NULL;
		    transaction = next) {
			next = transaction->next;
			if (transaction_terminal(transaction->summary.state)) {
				unlink_transaction_locked(transaction);
				removed++;
			}
		}
	}
	pthread_mutex_unlock(&store.lock);
	return removed;
}

static int
copy_message_view(const struct stored_message *source,
	struct capture_message_view *destination)
{
	memset(destination, 0, sizeof(*destination));
	if (source->start_line != NULL) {
		destination->start_line = duplicate_text(source->start_line);
		if (destination->start_line == NULL)
			return -1;
	}
	if (source->headers != NULL) {
		destination->headers = duplicate_text(source->headers);
		if (destination->headers == NULL)
			return -1;
	}
	if (source->body_len != 0) {
		destination->body = malloc(source->body_len);
		if (destination->body == NULL)
			return -1;
		memcpy(destination->body, source->body, source->body_len);
	}
	destination->body_len = source->body_len;
	destination->body_total = source->body_total;
	copy_text(destination->content_type, sizeof(destination->content_type),
	    source->content_type);
	copy_text(destination->content_encoding,
	    sizeof(destination->content_encoding), source->content_encoding);
	destination->headers_truncated = source->headers_truncated;
	destination->body_truncated = source->body_truncated;
	destination->binary = source->binary;
	return 0;
}

int
capture_get_transaction(uint64_t id, struct capture_transaction_view *view)
{
	struct stored_connection *connection;
	struct stored_transaction *transaction;

	if (view == NULL)
		return -1;
	memset(view, 0, sizeof(*view));
	pthread_mutex_lock(&store.lock);
	transaction = store.initialized ? find_transaction_locked(id) : NULL;
	if (transaction == NULL) {
		pthread_mutex_unlock(&store.lock);
		return -1;
	}
	view->summary = transaction->summary;
	connection = find_connection_locked(transaction->summary.connection_id);
	if (connection != NULL)
		view->connection = connection->view;
	if (copy_message_view(&transaction->request, &view->request) == -1 ||
	    copy_message_view(&transaction->response, &view->response) == -1) {
		pthread_mutex_unlock(&store.lock);
		capture_free_transaction(view);
		return -1;
	}
	pthread_mutex_unlock(&store.lock);
	return 0;
}

void
capture_free_transaction(struct capture_transaction_view *view)
{
	if (view == NULL)
		return;
	free(view->request.start_line);
	free(view->request.headers);
	free(view->request.body);
	free(view->response.start_line);
	free(view->response.headers);
	free(view->response.body);
	memset(view, 0, sizeof(*view));
}

size_t
capture_memory_used(void)
{
	size_t used;

	pthread_mutex_lock(&store.lock);
	used = store.memory_used;
	pthread_mutex_unlock(&store.lock);
	return used;
}
