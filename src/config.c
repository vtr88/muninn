#include "muninn.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#define PASSTHROUGH_MAX 64
#define PASSTHROUGH_HOST_MAX 256

/*
 * A configuracao e escrita uma vez por main antes de qualquer thread nascer.
 * Depois disso os trabalhadores apenas leem estes campos, portanto nao ha
 * necessidade de mutex.
 */
static int insecure_upstream;
static char passthrough[PASSTHROUGH_MAX][PASSTHROUGH_HOST_MAX];
static size_t passthrough_count;

void
config_usage(void)
{
	puts("uso:");
	puts("  muninn [--insecure-upstream] [--passthrough HOST]...");
	puts("  muninn ca create");
	puts("  muninn ca show");
	puts("  muninn ca fingerprint");
}

static int
add_passthrough(const char *host)
{
	if (host == NULL || *host == '\0' || strlen(host) >=
	    PASSTHROUGH_HOST_MAX || passthrough_count == PASSTHROUGH_MAX)
		return -1;
	if (strncmp(host, "*.", 2) == 0 && host[2] == '\0')
		return -1;
	snprintf(passthrough[passthrough_count], PASSTHROUGH_HOST_MAX, "%s",
	    host);
	passthrough_count++;
	return 0;
}

int
config_parse(int argc, char **argv, enum app_mode *mode)
{
	int i;

	if (mode == NULL)
		return -1;
	*mode = APP_RUN;
	if (argc == 2 && (strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0)) {
		*mode = APP_HELP;
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "ca") == 0) {
		if (argc != 3)
			return -1;
		if (strcmp(argv[2], "create") == 0)
			*mode = APP_CA_CREATE;
		else if (strcmp(argv[2], "show") == 0)
			*mode = APP_CA_SHOW;
		else if (strcmp(argv[2], "fingerprint") == 0)
			*mode = APP_CA_FINGERPRINT;
		else
			return -1;
		return 0;
	}

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--insecure-upstream") == 0) {
			insecure_upstream = 1;
		} else if (strcmp(argv[i], "--passthrough") == 0) {
			if (++i == argc || add_passthrough(argv[i]) == -1)
				return -1;
		} else {
			return -1;
		}
	}
	return 0;
}

int
config_insecure_upstream(void)
{
	return insecure_upstream;
}

/*
 * Um padrao comum significa correspondencia exata. "*.example.com" cobre
 * subdominios, mas nao o dominio raiz; isso evita ampliar o bypass sem querer.
 */
int
config_host_passthrough(const char *host)
{
	const char *pattern, *suffix;
	size_t host_len, i, suffix_len;

	if (host == NULL)
		return 0;
	host_len = strlen(host);
	for (i = 0; i < passthrough_count; i++) {
		pattern = passthrough[i];
		if (strncasecmp(pattern, "*.", 2) != 0) {
			if (strcasecmp(pattern, host) == 0)
				return 1;
			continue;
		}
		suffix = pattern + 1;
		suffix_len = strlen(suffix);
		if (host_len > suffix_len &&
		    strcasecmp(host + host_len - suffix_len, suffix) == 0)
			return 1;
	}
	return 0;
}
