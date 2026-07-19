#include "capture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: falhou: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

/* Exercita uma transacao inteira e as copias entregues para a futura TUI. */
static void
test_complete_transaction(void)
{
	static const unsigned char request_body[] = "abcdef";
	static const unsigned char response_body[] = { 'A', 0, 'B' };
	struct capture_connection_view *connections;
	struct capture_transaction_summary *summaries;
	struct capture_transaction_view view;
	struct capture_limits limits = { 4096, 4, 256, 8, 4 };
	size_t connection_count, summary_count;
	uint64_t id;

	CHECK(capture_init(&limits) == 0);
	CHECK(capture_connection_open(10, "127.0.0.1", "54321") == 0);
	capture_connection_target(10, "example.test", "443", 1, 0);
	capture_connection_tls(10, 1, "TLSv1.3", "TLS_AES_256_GCM_SHA384",
	    "http/1.1", 1);
	capture_connection_tls(10, 0, "TLSv1.3", "TLS_AES_128_GCM_SHA256",
	    "http/1.1", -2);

	id = capture_request_begin(10, "POST", "/submit", "HTTP/1.1");
	CHECK(id != 0);
	capture_header(id, 0, "Host: example.test");
	capture_header(id, 0, "Content-Type: text/plain; charset=utf-8");
	capture_headers_complete(id, 0);
	capture_body(id, 0, request_body, sizeof(request_body) - 1);
	capture_request_complete(id);
	capture_response_begin(id, "HTTP/1.1", 201, "Created");
	capture_header(id, 1, "Content-Type: application/octet-stream");
	capture_header(id, 1, "Content-Encoding: gzip");
	capture_headers_complete(id, 1);
	capture_body(id, 1, response_body, sizeof(response_body));
	capture_response_complete(id, 0);
	capture_connection_close(10);

	connections = NULL;
	connection_count = 0;
	CHECK(capture_list_connections(&connections, &connection_count) == 0);
	CHECK(connection_count == 1);
	if (connection_count == 1) {
		CHECK(connections[0].active == 0);
		CHECK(strcmp(connections[0].target_host, "example.test") == 0);
		CHECK(connections[0].is_tls == 1);
		CHECK(connections[0].upstream_tls.present == 1);
		CHECK(connections[0].upstream_tls.verified == 1);
		CHECK(strcmp(connections[0].upstream_tls.alpn, "http/1.1") == 0);
	}
	free(connections);

	summaries = NULL;
	summary_count = 0;
	CHECK(capture_list_transactions(&summaries, &summary_count) == 0);
	CHECK(summary_count == 1);
	if (summary_count == 1) {
		CHECK(summaries[0].state == CAPTURE_COMPLETE);
		CHECK(summaries[0].status == 201);
		CHECK(summaries[0].request_body_total == 6);
		CHECK(summaries[0].request_body_stored == 4);
		CHECK(summaries[0].request_truncated == 1);
	}
	free(summaries);

	CHECK(capture_get_transaction(id, &view) == 0);
	CHECK(strcmp(view.request.start_line, "POST /submit HTTP/1.1") == 0);
	CHECK(strstr(view.request.headers, "Host: example.test\r\n") != NULL);
	CHECK(strcmp(view.request.content_type,
	    "text/plain; charset=utf-8") == 0);
	CHECK(view.request.body_len == 4);
	CHECK(memcmp(view.request.body, "abcd", 4) == 0);
	CHECK(view.request.body_total == 6);
	CHECK(view.request.body_truncated == 1);
	CHECK(view.response.binary == 1);
	CHECK(view.response.body_len == 3);
	CHECK(strcmp(view.response.content_type,
	    "application/octet-stream") == 0);
	CHECK(strcmp(view.response.content_encoding, "gzip") == 0);
	capture_free_transaction(&view);
	summaries = NULL;
	summary_count = 0;
	CHECK(capture_list_transactions_matching(
	    "host:example.test method:POST status:201", &summaries,
	    &summary_count) == 0);
	CHECK(summary_count == 1);
	free(summaries);
	summaries = NULL;
	CHECK(capture_list_transactions_matching("application/octet-stream",
	    &summaries, &summary_count) == 0);
	CHECK(summary_count == 1);
	free(summaries);
	summaries = NULL;
	CHECK(capture_list_transactions_matching("state:erro", &summaries,
	    &summary_count) == 0);
	CHECK(summary_count == 0);
	free(summaries);
	CHECK(capture_memory_used() > 0);
	CHECK(capture_clear() == 1);
	CHECK(capture_list_transactions(&summaries, &summary_count) == 0);
	CHECK(summary_count == 0);
	free(summaries);
	capture_cleanup();
	CHECK(capture_memory_used() == 0);
}

/* O limite remove o registro terminal mais antigo, nunca uma request ativa. */
static void
test_eviction_and_interruption(void)
{
	struct capture_transaction_summary *summaries;
	struct capture_transaction_view view;
	struct capture_limits limits = { 2048, 64, 128, 2, 2 };
	size_t count;
	uint64_t first, second, third;

	CHECK(capture_init(&limits) == 0);
	CHECK(capture_connection_open(20, "127.0.0.1", "60000") == 0);
	first = capture_request_begin(20, "GET", "/first", "HTTP/1.1");
	capture_request_complete(first);
	capture_response_begin(first, "HTTP/1.1", 200, "OK");
	capture_response_complete(first, 0);

	second = capture_request_begin(20, "GET", "/second", "HTTP/1.1");
	capture_request_complete(second);
	third = capture_request_begin(20, "GET", "/third", "HTTP/1.1");
	CHECK(first != 0 && second != 0 && third != 0);
	CHECK(capture_get_transaction(first, &view) == -1);
	CHECK(capture_get_transaction(second, &view) == 0);
	capture_free_transaction(&view);

	/* Fechar a conexao explica por que as duas requests ficaram sem resposta. */
	capture_connection_close(20);
	summaries = NULL;
	count = 0;
	CHECK(capture_list_transactions(&summaries, &count) == 0);
	CHECK(count == 2);
	if (count == 2) {
		CHECK(summaries[0].state == CAPTURE_INTERRUPTED);
		CHECK(summaries[1].state == CAPTURE_INTERRUPTED);
	}
	free(summaries);
	capture_cleanup();
}

/* O orcamento global tambem provoca eviction e depois truncamento controlado. */
static void
test_global_memory_budget(void)
{
	unsigned char body[100];
	struct capture_transaction_view view;
	struct capture_limits limits = { 64, 128, 128, 4, 1 };
	uint64_t first, second;

	memset(body, 'x', sizeof(body));
	CHECK(capture_init(&limits) == 0);
	CHECK(capture_connection_open(40, "127.0.0.1", "62000") == 0);
	first = capture_request_begin(40, "POST", "/old", "HTTP/1.1");
	capture_body(first, 0, body, 40);
	capture_request_complete(first);
	capture_response_begin(first, "HTTP/1.1", 204, "No Content");
	capture_response_complete(first, 0);

	/* A nova start-line precisa de espaco e pode remover a primeira completa. */
	second = capture_request_begin(40, "POST", "/new", "HTTP/1.1");
	CHECK(second != 0);
	CHECK(capture_get_transaction(first, &view) == -1);
	capture_body(second, 0, body, sizeof(body));
	CHECK(capture_memory_used() <= limits.global_bytes);
	CHECK(capture_get_transaction(second, &view) == 0);
	CHECK(view.request.body_total == sizeof(body));
	CHECK(view.request.body_truncated == 1);
	capture_free_transaction(&view);
	capture_connection_close(40);
	capture_cleanup();
}

/* Entradas invalidas devem falhar sem deixar um store parcialmente ativo. */
static void
test_invalid_limits(void)
{
	struct capture_limits limits = { 0, 1, 1, 1, 1 };

	CHECK(capture_init(&limits) == -1);
	CHECK(capture_connection_open(1, "local", "1") == -1);
	CHECK(capture_memory_used() == 0);
	capture_cleanup();
}

int
main(void)
{
	test_complete_transaction();
	test_eviction_and_interruption();
	test_global_memory_budget();
	test_invalid_limits();

	if (failures != 0) {
		fprintf(stderr, "%d teste(s) falharam\n", failures);
		return 1;
	}
	puts("capture_test: ok");
	return 0;
}
