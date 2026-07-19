#include "muninn.h"

#include <sys/time.h>

#include <ctype.h>
#include <curses.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static struct logbuf logs[2];
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static int active_tab = SIDE_C2S;

/* ------------------------------------------------------------------------- */
/* Log e TUI                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * O log e um ring buffer simples por aba. A TUI le esse buffer enquanto as
 * threads de rede escrevem nele, entao protegemos tudo com um mutex.
 */
void
log_add(enum side side, const char *fmt, ...)
{
	struct logbuf *l = &logs[side];
	struct timeval tv;
	struct tm tm;
	char msg[LOG_LINE - 48];
	char stamp[32];
	va_list ap;
	int idx;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(stamp, sizeof(stamp), "%H:%M:%S", &tm);

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	pthread_mutex_lock(&log_lock);
	if (l->count < LOG_LINES) {
		idx = (l->start + l->count) % LOG_LINES;
		l->count++;
	} else {
		idx = l->start;
		l->start = (l->start + 1) % LOG_LINES;
	}
	snprintf(l->line[idx], LOG_LINE, "%s.%03ld %.180s", stamp,
	    (long)(tv.tv_usec / 1000), msg);
	pthread_mutex_unlock(&log_lock);
}

/*
 * Mostra bytes como texto quando possivel, e escapa o resto. Isso nao tenta ser
 * um parser HTTP completo; e so uma visao rapida do trafego que passou.
 */
void
log_bytes(enum side side, int id, const unsigned char *buf, size_t len)
{
	char out[LOG_LINE];
	size_t i, pos;

	pos = snprintf(out, sizeof(out), "#%d %zu bytes: ", id, len);
	for (i = 0; i < len && pos + 5 < sizeof(out); i++) {
		unsigned char c = buf[i];

		if (c == '\r') {
			out[pos++] = '\\';
			out[pos++] = 'r';
		} else if (c == '\n') {
			out[pos++] = '\\';
			out[pos++] = 'n';
			out[pos++] = ' ';
		} else if (isprint(c) || c == '\t') {
			out[pos++] = (char)c;
		} else {
			pos += snprintf(out + pos, sizeof(out) - pos, "\\x%02x", c);
		}
	}
	if (i < len && pos + 4 < sizeof(out)) {
		out[pos++] = '.';
		out[pos++] = '.';
		out[pos++] = '.';
	}
	out[pos] = '\0';
	log_add(side, "%s", out);
}

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
		init_pair(1, COLOR_BLACK, COLOR_CYAN);
		init_pair(2, COLOR_CYAN, -1);
	}
}

void
tui_input(void)
{
	int ch;

	while ((ch = getch()) != ERR) {
		if (ch == 'q' || ch == 'Q')
			running = 0;
		else if (ch == '\t' || ch == KEY_LEFT || ch == KEY_RIGHT)
			active_tab = active_tab == SIDE_C2S ? SIDE_S2C : SIDE_C2S;
	}
}

void
tui_draw(void)
{
	char copy[LOG_LINES][LOG_LINE];
	struct logbuf *l = &logs[active_tab];
	int rows, cols, i, n, idx, first, count;

	getmaxyx(stdscr, rows, cols);
	erase();

	if (has_colors())
		attron(COLOR_PAIR(active_tab == SIDE_C2S ? 1 : 2));
	mvaddnstr(0, 0, " C->S ", cols);
	if (has_colors()) {
		attroff(COLOR_PAIR(active_tab == SIDE_C2S ? 1 : 2));
		attron(COLOR_PAIR(active_tab == SIDE_S2C ? 1 : 2));
	}
	mvaddnstr(0, 7, " S->C ", cols - 7);
	if (has_colors())
		attroff(COLOR_PAIR(active_tab == SIDE_S2C ? 1 : 2));
	mvprintw(0, 16, " %s:%s  tab troca  q sai  CA: %s",
	    LISTEN_HOST, LISTEN_PORT, CA_CERT_FILE);
	mvhline(1, 0, ACS_HLINE, cols);

	n = rows - 3;
	if (n < 1) {
		refresh();
		return;
	}

	/*
	 * Copiamos as linhas para uma area local e soltamos o mutex antes de
	 * desenhar. Assim a TUI nao segura as threads de rede por muito tempo.
	 */
	pthread_mutex_lock(&log_lock);
	count = l->count;
	first = count > n ? count - n : 0;
	for (i = 0; i < n && first + i < count; i++) {
		idx = (l->start + first + i) % LOG_LINES;
		snprintf(copy[i], sizeof(copy[i]), "%s", l->line[idx]);
	}
	pthread_mutex_unlock(&log_lock);

	for (i = 0; i < n && first + i < count; i++)
		mvaddnstr(2 + i, 0, copy[i], cols - 1);
	refresh();
}

