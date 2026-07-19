#include "muninn.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* O fuzz nao precisa inicializar ncurses; eventos sao deliberadamente vazios. */
void
log_add(enum side side, const char *format, ...)
{
	(void)side;
	(void)format;
}

static void
feed_by_fragments(struct http_observer *observer, enum side side,
	const uint8_t *data, size_t size, size_t fragment)
{
	size_t offset, take;

	for (offset = 0; offset < size; offset += take) {
		take = size - offset;
		if (take > fragment)
			take = fragment;
		http_observer_feed(observer, side, data + offset, take);
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const unsigned char request[] =
	    "GET /fuzz HTTP/1.1\r\nHost: fuzz.test\r\n\r\n";
	struct http_observer *observer;

	if (size > 1024U * 1024U)
		return 0;
	(void)capture_init(NULL);
	(void)capture_connection_open(1, "127.0.0.1", "50000");
	capture_connection_target(1, "fuzz.test", "80", 0, 0);

	/* Primeiro interpreta a entrada como request, com fragmentos variaveis. */
	observer = http_observer_new(1);
	if (observer != NULL) {
		feed_by_fragments(observer, SIDE_C2S, data, size,
		    size == 0 ? 1 : data[0] % 31U + 1U);
		http_observer_eof(observer, SIDE_C2S);
		http_observer_free(observer);
	}

	/* Depois fornece uma request valida e usa os mesmos bytes como response. */
	observer = http_observer_new(1);
	if (observer != NULL) {
		http_observer_feed(observer, SIDE_C2S, request,
		    sizeof(request) - 1);
		feed_by_fragments(observer, SIDE_S2C, data, size,
		    size < 2 ? 1 : data[1] % 31U + 1U);
		http_observer_eof(observer, SIDE_S2C);
		http_observer_free(observer);
	}
	capture_connection_close(1);
	capture_cleanup();
	return 0;
}

#ifdef FUZZ_STANDALONE
int
main(void)
{
	uint8_t *data;
	size_t capacity, size;

	capacity = 1024U * 1024U;
	data = malloc(capacity);
	if (data == NULL)
		return 1;
	size = fread(data, 1, capacity, stdin);
	(void)LLVMFuzzerTestOneInput(data, size);
	free(data);
	puts("http_parser_fuzz: ok");
	return 0;
}
#endif
