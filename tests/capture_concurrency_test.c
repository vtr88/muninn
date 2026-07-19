#include "capture.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WRITERS 4
#define TRANSACTIONS_PER_WRITER 100

static int failures;
static int writers_done;
static pthread_mutex_t done_lock = PTHREAD_MUTEX_INITIALIZER;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: falhou: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

static void *
writer_thread(void *argument)
{
	long number;
	char host[64], target[64];
	int connection_id, i;
	uint64_t id;

	number = (long)argument;
	connection_id = 100 + (int)number;
	(void)snprintf(host, sizeof(host), "worker-%ld.test", number);
	if (capture_connection_open(connection_id, "127.0.0.1", "50000") == 0) {
		capture_connection_target(connection_id, host, "80", 0, 0);
		for (i = 0; i < TRANSACTIONS_PER_WRITER; i++) {
			(void)snprintf(target, sizeof(target), "/item/%d", i);
			id = capture_request_begin(connection_id, "GET", target,
			    "HTTP/1.1");
			capture_header(id, 0, "Host: worker.test");
			capture_headers_complete(id, 0);
			capture_request_complete(id);
			capture_response_begin(id, "HTTP/1.1", 200, "OK");
			capture_header(id, 1, "Content-Type: text/plain");
			capture_headers_complete(id, 1);
			capture_body(id, 1, (const unsigned char *)"ok", 2);
			capture_response_complete(id, 0);
		}
		capture_connection_close(connection_id);
	}
	pthread_mutex_lock(&done_lock);
	writers_done++;
	pthread_mutex_unlock(&done_lock);
	return NULL;
}

static void *
reader_thread(void *argument)
{
	struct capture_transaction_summary *transactions;
	struct capture_transaction_view view;
	size_t count;
	int done;

	(void)argument;
	for (;;) {
		transactions = NULL;
		count = 0;
		if (capture_list_transactions_matching("status:200", &transactions,
		    &count) == 0 && count != 0) {
			if (capture_get_transaction(transactions[count - 1].id,
			    &view) == 0)
				capture_free_transaction(&view);
		}
		free(transactions);
		pthread_mutex_lock(&done_lock);
		done = writers_done == WRITERS;
		pthread_mutex_unlock(&done_lock);
		if (done)
			break;
	}
	return NULL;
}

int
main(void)
{
	struct capture_transaction_summary *transactions;
	struct capture_limits limits = {
		4U * 1024U * 1024U, 1024U, 1024U,
		WRITERS * TRANSACTIONS_PER_WRITER, WRITERS
	};
	pthread_t reader, writers[WRITERS];
	size_t count, i;

	CHECK(capture_init(&limits) == 0);
	CHECK(pthread_create(&reader, NULL, reader_thread, NULL) == 0);
	for (i = 0; i < WRITERS; i++)
		CHECK(pthread_create(&writers[i], NULL, writer_thread,
		    (void *)(long)i) == 0);
	for (i = 0; i < WRITERS; i++)
		CHECK(pthread_join(writers[i], NULL) == 0);
	CHECK(pthread_join(reader, NULL) == 0);

	transactions = NULL;
	count = 0;
	CHECK(capture_list_transactions(&transactions, &count) == 0);
	CHECK(count == WRITERS * TRANSACTIONS_PER_WRITER);
	for (i = 0; i < count; i++)
		CHECK(transactions[i].state == CAPTURE_COMPLETE);
	free(transactions);
	CHECK(capture_memory_used() <= limits.global_bytes);
	capture_cleanup();
	if (failures != 0)
		return 1;
	puts("capture_concurrency_test: ok");
	return 0;
}
