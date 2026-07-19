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
		"--passthrough", "*.example.com"
	};

	CHECK(config_parse(6, argv, &mode) == 0);
	CHECK(mode == APP_RUN);
	CHECK(config_insecure_upstream() == 1);
	CHECK(config_host_passthrough("exact.example") == 1);
	CHECK(config_host_passthrough("EXACT.EXAMPLE") == 1);
	CHECK(config_host_passthrough("www.example.com") == 1);
	CHECK(config_host_passthrough("deep.www.example.com") == 1);
	CHECK(config_host_passthrough("example.com") == 0);
	CHECK(config_host_passthrough("notexample.com") == 0);

	if (failures != 0)
		return 1;
	puts("config_test: ok");
	return 0;
}
