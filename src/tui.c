#include "muninn.h"
#include "decode.h"
#include "tui_view.h"

#include <sys/time.h>

#include <ctype.h>
#include <curses.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum tui_screen {
	TUI_HISTORY,
	TUI_EVENTS
};

enum tui_message {
	TUI_REQUEST,
	TUI_RESPONSE
};

/* Cores possuem significado consistente nas duas telas. */
enum tui_color {
	PAIR_ACTIVE = 1,
	PAIR_ACCENT,
	PAIR_SELECTED,
	PAIR_ERROR,
	PAIR_WARNING
};

static struct logbuf logs[2];
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static enum tui_screen active_screen = TUI_HISTORY;
static enum tui_message active_message = TUI_REQUEST;
static int active_event_side = SIDE_C2S;
static uint64_t selected_transaction_id;
static size_t list_offset;
static size_t detail_offset;
static size_t event_offset;
static char filter_query[128];
static int editing_filter;

/* O body selecionado e decodificado somente quando sua identidade muda. */
static struct {
	uint64_t transaction_id;
	enum tui_message message;
	uint64_t body_total;
	size_t body_len;
	char encoding[64];
	struct body_decode_view decoded;
} decode_cache;

static void
clear_decode_cache(void)
{
	body_decode_free(&decode_cache.decoded);
	memset(&decode_cache, 0, sizeof(decode_cache));
}

/* ------------------------------------------------------------------------- */
/* Log de eventos                                                            */
/* ------------------------------------------------------------------------- */

/*
 * As threads de rede continuam produzindo mensagens operacionais. O ring
 * buffer evita crescimento ilimitado e um mutex curto protege cada insercao.
 */
void
log_add(enum side side, const char *fmt, ...)
{
	struct logbuf *log;
	struct timeval tv;
	struct tm tm;
	char message[LOG_LINE - 48];
	char stamp[32];
	va_list arguments;
	int index;

	log = &logs[side];
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(stamp, sizeof(stamp), "%H:%M:%S", &tm);

	va_start(arguments, fmt);
	vsnprintf(message, sizeof(message), fmt, arguments);
	va_end(arguments);

	pthread_mutex_lock(&log_lock);
	if (log->count < LOG_LINES) {
		index = (log->start + log->count) % LOG_LINES;
		log->count++;
	} else {
		index = log->start;
		log->start = (log->start + 1) % LOG_LINES;
	}
	snprintf(log->line[index], LOG_LINE, "%s.%03ld %.180s", stamp,
	    (long)(tv.tv_usec / 1000), message);
	pthread_mutex_unlock(&log_lock);
}

/* Esta visualizacao curta pertence ao log, nao ao historico estruturado. */
void
log_bytes(enum side side, int id, const unsigned char *buffer, size_t length)
{
	char output[LOG_LINE];
	size_t i, position;

	position = (size_t)snprintf(output, sizeof(output), "#%d %zu bytes: ",
	    id, length);
	for (i = 0; i < length && position + 5 < sizeof(output); i++) {
		unsigned char byte = buffer[i];

		if (byte == '\r') {
			output[position++] = '\\';
			output[position++] = 'r';
		} else if (byte == '\n') {
			output[position++] = '\\';
			output[position++] = 'n';
			output[position++] = ' ';
		} else if (isprint(byte) || byte == '\t') {
			output[position++] = (char)byte;
		} else {
			position += (size_t)snprintf(output + position,
			    sizeof(output) - position, "\\x%02x", byte);
		}
	}
	if (i < length && position + 4 < sizeof(output)) {
		output[position++] = '.';
		output[position++] = '.';
		output[position++] = '.';
	}
	output[position] = '\0';
	log_add(side, "%s", output);
}

/* ------------------------------------------------------------------------- */
/* Estado e entrada                                                          */
/* ------------------------------------------------------------------------- */

void
tui_init(void)
{
	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	curs_set(0);

	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(PAIR_ACTIVE, COLOR_BLACK, COLOR_CYAN);
		init_pair(PAIR_ACCENT, COLOR_CYAN, -1);
		init_pair(PAIR_SELECTED, COLOR_BLACK, COLOR_WHITE);
		init_pair(PAIR_ERROR, COLOR_RED, -1);
		init_pair(PAIR_WARNING, COLOR_YELLOW, -1);
	}
}

void
tui_cleanup(void)
{
	clear_decode_cache();
}

/* Busca um snapshot apenas quando uma tecla realmente move a selecao. */
static void
move_selection(int delta)
{
	struct capture_transaction_summary *transactions;
	size_t count;

	transactions = NULL;
	count = 0;
	if (capture_list_transactions_matching(filter_query, &transactions,
	    &count) == 0) {
		(void)tui_selection_move(transactions, count,
		    &selected_transaction_id, delta);
		detail_offset = 0;
	}
	free(transactions);
}

static void
select_edge(int newest)
{
	struct capture_transaction_summary *transactions;
	size_t count;

	transactions = NULL;
	count = 0;
	if (capture_list_transactions_matching(filter_query, &transactions,
	    &count) == 0 && count != 0) {
		selected_transaction_id = transactions[newest ? count - 1 : 0].id;
		detail_offset = 0;
	}
	free(transactions);
}

static void
filter_input(int key)
{
	size_t length;

	length = strlen(filter_query);
	if (key == '\n' || key == '\r' || key == KEY_ENTER || key == 27) {
		editing_filter = 0;
		(void)curs_set(0);
		return;
	}
	if (key == KEY_BACKSPACE || key == 127 || key == '\b') {
		if (length != 0)
			filter_query[length - 1] = '\0';
	} else if (key == 21) { /* Ctrl-U limpa a linha durante a edicao. */
		filter_query[0] = '\0';
	} else if (key >= 0x20 && key <= 0x7e &&
	    length + 1 < sizeof(filter_query)) {
		filter_query[length] = (char)key;
		filter_query[length + 1] = '\0';
	}
	selected_transaction_id = 0;
	list_offset = 0;
	detail_offset = 0;
}

static void
history_input(int key)
{
	switch (key) {
	case '\t':
		active_message = active_message == TUI_REQUEST ?
		    TUI_RESPONSE : TUI_REQUEST;
		detail_offset = 0;
		break;
	case KEY_LEFT:
		active_message = TUI_REQUEST;
		detail_offset = 0;
		break;
	case KEY_RIGHT:
		active_message = TUI_RESPONSE;
		detail_offset = 0;
		break;
	case KEY_UP:
	case 'k':
		move_selection(-1);
		break;
	case KEY_DOWN:
	case 'j':
		move_selection(1);
		break;
	case KEY_HOME:
	case 'g':
		select_edge(0);
		break;
	case KEY_END:
	case 'G':
		select_edge(1);
		break;
	case KEY_PPAGE:
	case 'u':
		detail_offset = detail_offset > 8 ? detail_offset - 8 : 0;
		break;
	case KEY_NPAGE:
	case 'd':
		if (detail_offset <= SIZE_MAX - 8)
			detail_offset += 8;
		break;
	}
}

static void
events_input(int key)
{
	switch (key) {
	case '\t':
	case KEY_LEFT:
	case KEY_RIGHT:
		active_event_side = active_event_side == SIDE_C2S ?
		    SIDE_S2C : SIDE_C2S;
		event_offset = 0;
		break;
	case KEY_UP:
	case 'k':
		if (event_offset < LOG_LINES - 1)
			event_offset++;
		break;
	case KEY_DOWN:
	case 'j':
		if (event_offset > 0)
			event_offset--;
		break;
	case KEY_PPAGE:
	case 'u':
		event_offset += event_offset <= LOG_LINES - 9 ? 8 : 0;
		break;
	case KEY_NPAGE:
	case 'd':
		event_offset = event_offset > 8 ? event_offset - 8 : 0;
		break;
	case KEY_END:
	case 'G':
		event_offset = 0;
		break;
	}
}

void
tui_input(void)
{
	int key;

	while ((key = getch()) != ERR) {
		if (editing_filter) {
			filter_input(key);
			continue;
		}
		if (key == 'q' || key == 'Q') {
			running = 0;
			continue;
		}
		if (key == 'e' || key == 'E') {
			active_screen = active_screen == TUI_HISTORY ?
			    TUI_EVENTS : TUI_HISTORY;
			continue;
		}
		if (active_screen == TUI_HISTORY && key == '/') {
			editing_filter = 1;
			(void)curs_set(1);
			continue;
		}
		if (active_screen == TUI_HISTORY && key == 'c') {
			filter_query[0] = '\0';
			selected_transaction_id = 0;
			list_offset = 0;
			detail_offset = 0;
			continue;
		}
		if (active_screen == TUI_HISTORY && key == 'C') {
			(void)capture_clear();
			clear_decode_cache();
			selected_transaction_id = 0;
			list_offset = 0;
			detail_offset = 0;
			continue;
		}
		if (active_screen == TUI_HISTORY)
			history_input(key);
		else
			events_input(key);
	}
}

/* ------------------------------------------------------------------------- */
/* Primitivas de desenho                                                     */
/* ------------------------------------------------------------------------- */

static void
draw_tab(int row, int column, const char *label, int active)
{
	if (has_colors())
		attron(COLOR_PAIR(active ? PAIR_ACTIVE : PAIR_ACCENT));
	if (active)
		attron(A_BOLD);
	mvaddstr(row, column, label);
	if (active)
		attroff(A_BOLD);
	if (has_colors())
		attroff(COLOR_PAIR(active ? PAIR_ACTIVE : PAIR_ACCENT));
}

static void
draw_header(size_t transaction_count, int columns)
{
	char memory[32], right[160];
	int right_column;

	tui_format_bytes(capture_memory_used(), memory, sizeof(memory));
	attron(A_BOLD);
	mvaddstr(0, 0, " Muninn ");
	attroff(A_BOLD);
	if (active_screen == TUI_HISTORY) {
		draw_tab(0, 9, " Request ", active_message == TUI_REQUEST);
		draw_tab(0, 19, " Response ", active_message == TUI_RESPONSE);
		(void)snprintf(right, sizeof(right),
		    "%zu transacoes | %s | %s:%s",
		    transaction_count, memory, LISTEN_HOST, LISTEN_PORT);
	} else {
		draw_tab(0, 9, " C->S ", active_event_side == SIDE_C2S);
		draw_tab(0, 16, " S->C ", active_event_side == SIDE_S2C);
		(void)snprintf(right, sizeof(right),
		    "%s:%s", LISTEN_HOST, LISTEN_PORT);
	}
	right_column = columns - (int)strlen(right) - 1;
	if (right_column > 29)
		mvaddnstr(0, right_column, right, columns - right_column - 1);
}

/*
 * Um viewport recebe linhas logicas, ignora as anteriores ao scroll e desenha
 * apenas as que cabem. Mesmo as linhas invisiveis sao contadas para limitar a
 * rolagem corretamente depois de resize.
 */
struct viewport {
	size_t first_line;
	size_t logical_line;
	int row;
	int end_row;
	int width;
};

static void
viewport_line(struct viewport *viewport, const char *text, size_t length)
{
	size_t consume, offset, take;

	if (viewport->width <= 0)
		return;
	if (length == 0) {
		if (viewport->logical_line >= viewport->first_line &&
		    viewport->row < viewport->end_row)
			viewport->row++;
		viewport->logical_line++;
		return;
	}
	offset = 0;
	while (offset < length) {
		take = length - offset;
		if (take > (size_t)viewport->width)
			take = (size_t)viewport->width;
		consume = take;
		if (offset + take < length) {
			size_t split;

			/* Prefere o ultimo espaco visivel dentro da largura. */
			for (split = take; split > 0; split--) {
				if (text[offset + split - 1] == ' ')
					break;
			}
			if (split > 1) {
				take = split - 1;
				consume = split;
				while (offset + consume < length &&
				    text[offset + consume] == ' ')
					consume++;
			}
		}
		if (viewport->logical_line >= viewport->first_line &&
		    viewport->row < viewport->end_row) {
			mvaddnstr(viewport->row, 1, text + offset, (int)take);
			viewport->row++;
		}
		viewport->logical_line++;
		offset += consume;
	}
}

static void
viewport_text(struct viewport *viewport, const char *text)
{
	const char *cursor, *line;
	size_t length;

	if (text == NULL || *text == '\0') {
		viewport_line(viewport, "", 0);
		return;
	}
	line = text;
	for (cursor = text;; cursor++) {
		if (*cursor == '\n' || *cursor == '\0') {
			length = (size_t)(cursor - line);
			if (length != 0 && line[length - 1] == '\r')
				length--;
			viewport_line(viewport, line, length);
			if (*cursor == '\0')
				break;
			line = cursor + 1;
		}
	}
}

/* Bodies textuais podem conter controles; convertemos somente esses para '.'. */
static void
viewport_body_text(struct viewport *viewport, const unsigned char *body,
	size_t length)
{
	char line[4096];
	size_t i, position, width;

	width = viewport->width < (int)sizeof(line) - 1 ?
	    (size_t)viewport->width : sizeof(line) - 1;
	position = 0;
	for (i = 0; i < length; i++) {
		unsigned char byte = body[i];

		if (byte == '\r')
			continue;
		if (byte == '\n') {
			viewport_line(viewport, line, position);
			position = 0;
			continue;
		}
		if (byte == '\t') {
			line[position++] = ' ';
		} else if (byte >= 0x20 && byte != 0x7f) {
			line[position++] = (char)byte;
		} else {
			line[position++] = '.';
		}
		if (position == width) {
			viewport_line(viewport, line, position);
			position = 0;
		}
	}
	if (position != 0 || length == 0)
		viewport_line(viewport, line, position);
}

static void
viewport_hexdump(struct viewport *viewport, const unsigned char *body,
	size_t length)
{
	char line[96];
	size_t consumed, offset;

	for (offset = 0; offset < length; offset += consumed) {
		consumed = tui_hexdump_line(body, length, offset, line,
		    sizeof(line));
		if (consumed == 0)
			break;
		viewport_line(viewport, line, strlen(line));
	}
}

/* ------------------------------------------------------------------------- */
/* Historico                                                                 */
/* ------------------------------------------------------------------------- */

static void
draw_transaction_row(int row, int columns,
	const struct capture_transaction_summary *transaction, int selected)
{
	char destination[1400], status[8], line[2048];
	const char *state;

	state = tui_state_name(transaction->state);
	tui_format_destination(transaction, destination, sizeof(destination));
	if (transaction->status == 0)
		(void)snprintf(status, sizeof(status), "-");
	else
		(void)snprintf(status, sizeof(status), "%d", transaction->status);
	if (columns >= 90) {
		(void)snprintf(line, sizeof(line), "%-6llu %-12.12s %-9.9s %-6s %.1900s",
		    (unsigned long long)transaction->id, state,
		    transaction->method, status, destination);
	} else {
		(void)snprintf(line, sizeof(line), "%-5llu %-9.9s %-7.7s %-4s %.1900s",
		    (unsigned long long)transaction->id, state,
		    transaction->method, status, destination);
	}
	if (selected) {
		if (has_colors())
			attron(COLOR_PAIR(PAIR_SELECTED));
		else
			attron(A_REVERSE);
	} else if (transaction->state == CAPTURE_ERROR && has_colors()) {
		attron(COLOR_PAIR(PAIR_ERROR));
	} else if (transaction->state == CAPTURE_INTERRUPTED && has_colors()) {
		attron(COLOR_PAIR(PAIR_WARNING));
	}
	mvaddnstr(row, 0, line, columns - 1);
	if (selected) {
		if (has_colors())
			attroff(COLOR_PAIR(PAIR_SELECTED));
		else
			attroff(A_REVERSE);
	} else if (transaction->state == CAPTURE_ERROR && has_colors()) {
		attroff(COLOR_PAIR(PAIR_ERROR));
	} else if (transaction->state == CAPTURE_INTERRUPTED && has_colors()) {
		attroff(COLOR_PAIR(PAIR_WARNING));
	}
}

static void
draw_connection_metadata(struct viewport *viewport,
	const struct capture_transaction_view *transaction)
{
	const struct capture_connection_view *connection;
	char line[768];

	connection = &transaction->connection;
	(void)snprintf(line, sizeof(line),
	    "Conexao #%d  %s:%s -> %s:%s  %s%s  %lld ms",
	    connection->id, connection->client_host, connection->client_port,
	    connection->target_host, connection->target_port,
	    connection->is_tls ? "TLS" : "HTTP",
	    connection->passthrough ? " passthrough" : "",
	    transaction->summary.duration_ms);
	viewport_text(viewport, line);
	if (connection->upstream_tls.present) {
		(void)snprintf(line, sizeof(line),
		    "Upstream: %s | %s | ALPN %s | certificado %s",
		    connection->upstream_tls.version,
		    connection->upstream_tls.cipher,
		    connection->upstream_tls.alpn[0] != '\0' ?
		    connection->upstream_tls.alpn : "nenhum",
		    tui_verify_name(connection->upstream_tls.verified));
		viewport_text(viewport, line);
	}
	if (connection->browser_tls.present) {
		(void)snprintf(line, sizeof(line),
		    "Navegador: %s | %s | ALPN %s",
		    connection->browser_tls.version,
		    connection->browser_tls.cipher,
		    connection->browser_tls.alpn[0] != '\0' ?
		    connection->browser_tls.alpn : "nenhum");
		viewport_text(viewport, line);
	}
}

static size_t
draw_message_document(int first_row, int end_row, int columns,
	const struct capture_transaction_view *transaction)
{
	const struct capture_message_view *message;
	const unsigned char *display_body;
	struct capture_message_view summary_message;
	struct viewport viewport;
	char summary[256], line[512];
	size_t display_length;
	int display_binary;

	message = active_message == TUI_REQUEST ? &transaction->request :
	    &transaction->response;
	if (decode_cache.transaction_id != transaction->summary.id ||
	    decode_cache.message != active_message ||
	    decode_cache.body_total != message->body_total ||
	    decode_cache.body_len != message->body_len ||
	    strcmp(decode_cache.encoding, message->content_encoding) != 0) {
		body_decode_free(&decode_cache.decoded);
		decode_cache.transaction_id = transaction->summary.id;
		decode_cache.message = active_message;
		decode_cache.body_total = message->body_total;
		decode_cache.body_len = message->body_len;
		(void)snprintf(decode_cache.encoding,
		    sizeof(decode_cache.encoding), "%s", message->content_encoding);
		(void)body_decode(message, BODY_DECODE_MAX_BYTES,
		    &decode_cache.decoded);
	}
	if (decode_cache.decoded.data != NULL) {
		display_body = decode_cache.decoded.data;
		display_length = decode_cache.decoded.length;
		display_binary = decode_cache.decoded.binary;
	} else {
		display_body = message->body;
		display_length = message->body_len;
		display_binary = message->binary;
	}
	viewport.first_line = detail_offset;
	viewport.logical_line = 0;
	viewport.row = first_row;
	viewport.end_row = end_row;
	viewport.width = columns - 2;

	draw_connection_metadata(&viewport, transaction);
	viewport_text(&viewport, "");
	viewport_text(&viewport, "Start-line");
	viewport_text(&viewport, message->start_line != NULL ?
	    message->start_line : "(ainda nao recebida)");
	viewport_text(&viewport, "");
	summary_message = *message;
	summary_message.binary = display_binary;
	tui_format_body_summary(&summary_message, summary, sizeof(summary));
	(void)snprintf(line, sizeof(line), "%s%s%s%s%s",
	    message->content_type[0] != '\0' ? message->content_type :
	    "Content-Type desconhecido", summary[0] != '\0' ? " | " : "",
	    summary, message->headers_truncated ? " | headers truncados" : "",
	    message->body_truncated ? " | body truncado" : "");
	viewport_text(&viewport, line);
	if (message->content_encoding[0] != '\0') {
		char decoded_size[32];

		tui_format_bytes(display_length, decoded_size,
		    sizeof(decoded_size));
		(void)snprintf(line, sizeof(line),
		    "Content-Encoding: %s | %s | exibindo %s",
		    message->content_encoding,
		    body_decode_status_name(decode_cache.decoded.status),
		    decoded_size);
		viewport_text(&viewport, line);
	}
	viewport_text(&viewport, "");
	viewport_text(&viewport, "Headers");
	viewport_text(&viewport, message->headers != NULL ? message->headers :
	    "(nenhum)");
	viewport_text(&viewport, "Body");
	if (display_length == 0) {
		viewport_text(&viewport, "(vazio)");
	} else if (display_binary) {
		viewport_hexdump(&viewport, display_body, display_length);
	} else {
		viewport_body_text(&viewport, display_body, display_length);
	}
	if (decode_cache.decoded.status == BODY_DECODE_PARTIAL ||
	    decode_cache.decoded.status == BODY_DECODE_LIMIT)
		viewport_text(&viewport,
		    "[representacao decodificada incompleta; dados brutos preservados]");
	if (message->body_truncated)
		viewport_text(&viewport,
		    "[conteudo restante nao armazenado; trafego foi encaminhado completo]");
	return viewport.logical_line;
}

static void
draw_history(struct capture_transaction_summary *transactions, size_t count,
	int rows, int columns)
{
	struct capture_transaction_view transaction;
	char destination[1400], title[1536];
	size_t detail_lines, index, list_height, max_detail_offset, visible;
	int detail_first, detail_title, divider, i;

	index = tui_selection_sync(transactions, count, &selected_transaction_id);
	if (filter_query[0] != '\0' || editing_filter) {
		char filter_line[256];

		(void)snprintf(filter_line, sizeof(filter_line), "Filtro%s: %s",
		    editing_filter ? "*" : "", filter_query);
		mvaddnstr(1, 0, filter_line, columns - 1);
	} else {
		mvprintw(1, 0, "Proxy ativo | CA: %s", CA_CERT_FILE);
	}
	mvhline(2, 0, ACS_HLINE, columns);
	attron(A_BOLD);
	if (columns >= 90)
		mvaddnstr(3, 0, "ID     ESTADO       METODO    STATUS DESTINO",
		    columns - 1);
	else
		mvaddnstr(3, 0, "ID    ESTADO    METODO  ST   DESTINO", columns - 1);
	attroff(A_BOLD);

	list_height = (size_t)(rows / 3);
	if (list_height < 4)
		list_height = 4;
	if (list_height > 10)
		list_height = 10;
	if (count == 0)
		list_offset = 0;
	else {
		if (index < list_offset)
			list_offset = index;
		if (index >= list_offset + list_height)
			list_offset = index - list_height + 1;
		if (list_offset + list_height > count)
			list_offset = count > list_height ? count - list_height : 0;
	}
	for (i = 0; i < (int)list_height; i++) {
		if (list_offset + (size_t)i >= count)
			break;
		draw_transaction_row(4 + i, columns,
		    &transactions[list_offset + (size_t)i],
		    list_offset + (size_t)i == index);
	}
	if (count == 0)
		mvaddnstr(5, 1, "Nenhuma transacao HTTP observada.", columns - 2);

	divider = 4 + (int)list_height;
	mvhline(divider, 0, ACS_HLINE, columns);
	detail_title = divider + 1;
	if (count == 0) {
		mvaddnstr(detail_title + 1, 1,
		    "Configure o navegador e abra um endereco HTTP ou HTTPS.",
		    columns - 2);
		return;
	}

	if (capture_get_transaction(selected_transaction_id, &transaction) == -1)
		return;
	tui_format_destination(&transaction.summary, destination,
	    sizeof(destination));
	attron(A_BOLD);
	(void)snprintf(title, sizeof(title), "#%llu %s %s  [%s]",
	    (unsigned long long)transaction.summary.id,
	    transaction.summary.method, destination,
	    tui_state_name(transaction.summary.state));
	mvaddnstr(detail_title, 1, title, columns - 2);
	attroff(A_BOLD);
	detail_first = detail_title + 1;
	for (i = detail_first; i < rows - 1; i++) {
		move(i, 0);
		clrtoeol();
	}
	detail_lines = draw_message_document(detail_first, rows - 1, columns,
	    &transaction);
	visible = rows - 1 > detail_first ?
	    (size_t)(rows - 1 - detail_first) : 0;
	max_detail_offset = detail_lines > visible ? detail_lines - visible : 0;
	if (detail_offset > max_detail_offset) {
		detail_offset = max_detail_offset;
		for (i = detail_first; i < rows - 1; i++) {
			move(i, 0);
			clrtoeol();
		}
		(void)draw_message_document(detail_first, rows - 1, columns,
		    &transaction);
	}
	mvprintw(rows - 1, columns > 24 ? columns - 24 : 0,
	    " detalhe %zu/%zu ", detail_offset + 1,
	    max_detail_offset + 1);
	capture_free_transaction(&transaction);
}

/* ------------------------------------------------------------------------- */
/* Eventos                                                                   */
/* ------------------------------------------------------------------------- */

static void
draw_events(int rows, int columns)
{
	char copy[LOG_LINES][LOG_LINE];
	struct logbuf *log;
	size_t available, first;
	int count, i, index, visible;

	log = &logs[active_event_side];
	mvaddnstr(1, 0, "Eventos operacionais", columns - 1);
	mvhline(2, 0, ACS_HLINE, columns);
	visible = rows - 4;
	if (visible < 1)
		return;

	/* Copia sob o mutex e desenha depois de solta-lo. */
	pthread_mutex_lock(&log_lock);
	count = log->count;
	available = count > visible ? (size_t)(count - visible) : 0;
	if (event_offset > available)
		event_offset = available;
	first = count > visible + (int)event_offset ?
	    (size_t)count - (size_t)visible - event_offset : 0;
	for (i = 0; i < visible && first + (size_t)i < (size_t)count; i++) {
		index = (log->start + (int)first + i) % LOG_LINES;
		(void)snprintf(copy[i], sizeof(copy[i]), "%s", log->line[index]);
	}
	pthread_mutex_unlock(&log_lock);
	for (i = 0; i < visible && first + (size_t)i < (size_t)count; i++)
		mvaddnstr(3 + i, 0, copy[i], columns - 1);
	if (count == 0)
		mvaddnstr(4, 1, "Nenhum evento nesta direcao.", columns - 2);
}

void
tui_draw(void)
{
	struct capture_transaction_summary *transactions;
	size_t count;
	int columns, rows;

	getmaxyx(stdscr, rows, columns);
	erase();
	transactions = NULL;
	count = 0;
	(void)capture_list_transactions_matching(filter_query, &transactions,
	    &count);
	if (count == 0)
		clear_decode_cache();
	draw_header(count, columns);
	if (rows < 14 || columns < 50) {
		mvaddnstr(3, 1,
		    "Terminal pequeno: use pelo menos 50 colunas por 14 linhas.",
		    columns > 2 ? columns - 2 : 0);
		free(transactions);
		refresh();
		return;
	}
	if (active_screen == TUI_HISTORY)
		draw_history(transactions, count, rows, columns);
	else
		draw_events(rows, columns);
	free(transactions);
	if (editing_filter) {
		int cursor_column = 9 + (int)strlen(filter_query);

		if (cursor_column >= columns)
			cursor_column = columns - 1;
		move(1, cursor_column);
	}
	refresh();
}
