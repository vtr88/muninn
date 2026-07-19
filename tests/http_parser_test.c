#include "muninn.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

/*
 * O parser escreve eventos no log da aplicacao. O teste nao precisa de
 * ncurses, portanto oferece este destino vazio e testa os contadores publicos.
 */
void
log_add(enum side side, const char *fmt, ...)
{
	(void)side;
	(void)fmt;
}

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: falhou: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

static void
feed_fragments(struct http_observer *observer, enum side side,
    const char *text, size_t fragment)
{
	size_t len, off, take;

	len = strlen(text);
	for (off = 0; off < len; off += take) {
		take = len - off;
		if (take > fragment)
			take = fragment;
		http_observer_feed(observer, side,
		    (const unsigned char *)text + off, take);
	}
}

static struct http_observer_stats
stats_of(struct http_observer *observer)
{
	struct http_observer_stats stats;

	http_observer_get_stats(observer, &stats);
	return stats;
}

static void
test_fixed_and_chunked_fragmented(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(1);
	CHECK(observer != NULL);
	feed_fragments(observer, SIDE_C2S,
	    "POST /submit HTTP/1.1\r\nHost: local\r\n"
	    "Content-Length: 5\r\n\r\nhello", 1);
	feed_fragments(observer, SIDE_S2C,
	    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	    "4\r\nWiki\r\n5;ext=yes\r\npedia\r\n0\r\n"
	    "X-Trailer: yes\r\n\r\n", 2);
	stats = stats_of(observer);
	CHECK(stats.requests == 1);
	CHECK(stats.responses == 1);
	CHECK(stats.request_body_bytes == 5);
	CHECK(stats.response_body_bytes == 9);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);
}

static void
test_keep_alive_head_and_204(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(2);
	feed_fragments(observer, SIDE_C2S,
	    "HEAD /metadata HTTP/1.1\r\nHost: local\r\n\r\n"
	    "GET /empty HTTP/1.1\r\nHost: local\r\n\r\n", 7);
	feed_fragments(observer, SIDE_S2C,
	    "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
	    "HTTP/1.1 204 No Content\r\nContent-Length: 20\r\n\r\n", 5);
	stats = stats_of(observer);
	CHECK(stats.requests == 2);
	CHECK(stats.responses == 2);
	CHECK(stats.response_body_bytes == 0);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);
}

static void
test_response_until_eof(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(3);
	feed_fragments(observer, SIDE_C2S,
	    "GET /legacy HTTP/1.0\r\nHost: local\r\n\r\n", 3);
	feed_fragments(observer, SIDE_S2C,
	    "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nabc", 4);
	stats = stats_of(observer);
	CHECK(stats.responses == 0);
	http_observer_eof(observer, SIDE_S2C);
	stats = stats_of(observer);
	CHECK(stats.responses == 1);
	CHECK(stats.response_body_bytes == 3);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);
}

static void
test_informational_response(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(4);
	feed_fragments(observer, SIDE_C2S,
	    "POST /create HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata", 6);
	feed_fragments(observer, SIDE_S2C,
	    "HTTP/1.1 100 Continue\r\n\r\n"
	    "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n", 8);
	stats = stats_of(observer);
	CHECK(stats.requests == 1);
	CHECK(stats.responses == 2);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);
}

static void
test_upgrade_becomes_opaque(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(5);
	feed_fragments(observer, SIDE_C2S,
	    "GET /chat HTTP/1.1\r\nConnection: Upgrade\r\n"
	    "Upgrade: websocket\r\n\r\n", 1);
	feed_fragments(observer, SIDE_S2C,
	    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
	    "Upgrade: websocket\r\n\r\nopaque bytes", 1);
	stats = stats_of(observer);
	CHECK(stats.requests == 1);
	CHECK(stats.responses == 1);
	CHECK(stats.tunneled == 1);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);
}

static void
test_content_length_lists_and_conflicts(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(6);
	feed_fragments(observer, SIDE_C2S,
	    "POST /ok HTTP/1.1\r\nContent-Length: 3, 3\r\n\r\nabc", 2);
	stats = stats_of(observer);
	CHECK(stats.requests == 1);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);

	observer = http_observer_new(7);
	feed_fragments(observer, SIDE_C2S,
	    "POST /bad HTTP/1.1\r\nContent-Length: 3\r\n"
	    "Content-Length: 4\r\n\r\n", 3);
	stats = stats_of(observer);
	CHECK(stats.parse_errors == 1);
	http_observer_free(observer);
}

static void
test_invalid_request_transfer_encoding(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(8);
	feed_fragments(observer, SIDE_C2S,
	    "POST /bad HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", 4);
	stats = stats_of(observer);
	CHECK(stats.parse_errors == 1);
	http_observer_free(observer);

	observer = http_observer_new(9);
	feed_fragments(observer, SIDE_C2S,
	    "POST /bad HTTP/1.1\r\n"
	    "Transfer-Encoding: chunked, gzip\r\n\r\n", 5);
	stats = stats_of(observer);
	CHECK(stats.parse_errors == 1);
	http_observer_free(observer);
}

static void
test_connect_and_205_have_no_body(void)
{
	struct http_observer *observer;
	struct http_observer_stats stats;

	observer = http_observer_new(10);
	feed_fragments(observer, SIDE_C2S,
	    "GET /reset HTTP/1.1\r\nHost: local\r\n\r\n", 3);
	feed_fragments(observer, SIDE_S2C,
	    "HTTP/1.1 205 Reset Content\r\n\r\n", 4);
	stats = stats_of(observer);
	CHECK(stats.responses == 1);
	CHECK(stats.response_body_bytes == 0);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);

	observer = http_observer_new(11);
	feed_fragments(observer, SIDE_C2S,
	    "CONNECT local:443 HTTP/1.1\r\nHost: local:443\r\n\r\n", 2);
	feed_fragments(observer, SIDE_S2C,
	    "HTTP/1.1 200 Connection Established\r\n\r\nopaque", 2);
	stats = stats_of(observer);
	CHECK(stats.requests == 1);
	CHECK(stats.responses == 1);
	CHECK(stats.tunneled == 1);
	CHECK(stats.parse_errors == 0);
	http_observer_free(observer);
}

int
main(void)
{
	test_fixed_and_chunked_fragmented();
	test_keep_alive_head_and_204();
	test_response_until_eof();
	test_informational_response();
	test_upgrade_becomes_opaque();
	test_content_length_lists_and_conflicts();
	test_invalid_request_transfer_encoding();
	test_connect_and_205_have_no_body();

	if (failures != 0) {
		fprintf(stderr, "%d teste(s) falharam\n", failures);
		return 1;
	}
	puts("http_parser_test: ok");
	return 0;
}
