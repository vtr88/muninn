#include "muninn.h"

#include <stdio.h>

static int failures;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: falhou: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

int
main(void)
{
	enum app_mode mode;
	char *argv[] = {
		"muninn",
		"--insecure-upstream",
		"--passthrough", "exact.example",
		"--passthrough", "*.example.com",
		"--max-memory", "16M",
		"--max-body", "128K",
		"--max-headers", "32K",
		"--max-transactions", "4000",
		"--max-connections", "700"
	};
	const struct capture_limits *limits;

	CHECK(config_parse(16, argv, &mode) == 0);
	CHECK(mode == APP_RUN);
	CHECK(config_insecure_upstream() == 1);
	CHECK(config_host_passthrough("exact.example") == 1);
	CHECK(config_host_passthrough("EXACT.EXAMPLE") == 1);
	CHECK(config_host_passthrough("www.example.com") == 1);
	CHECK(config_host_passthrough("deep.www.example.com") == 1);
	CHECK(config_host_passthrough("example.com") == 0);
	CHECK(config_host_passthrough("notexample.com") == 0);
	limits = config_capture_limits();
	CHECK(limits->global_bytes == 16U * 1024U * 1024U);
	CHECK(limits->body_bytes == 128U * 1024U);
	CHECK(limits->header_bytes == 32U * 1024U);
	CHECK(limits->max_transactions == 4000);
	CHECK(limits->max_connections == 700);

	{
		char *bad[] = { "muninn", "--max-body", "0" };
		CHECK(config_parse(3, bad, &mode) == -1);
	}
	{
		char *version[] = { "muninn", "--version" };
		CHECK(config_parse(2, version, &mode) == 0);
		CHECK(mode == APP_VERSION);
	}

	if (failures != 0)
		return 1;
	puts("config_test: ok");
	return 0;
}
