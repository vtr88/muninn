#include "muninn.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
static struct capture_limits capture_limits;

void
config_usage(void)
{
	puts("uso:");
	puts("  muninn [opcoes]");
	puts("  muninn ca create");
	puts("  muninn ca show");
	puts("  muninn ca fingerprint");
	puts("");
	puts("opcoes:");
	puts("  --insecure-upstream       nao verifica certificados upstream");
	puts("  --passthrough HOST        nao intercepta TLS para HOST");
	puts("  --max-memory TAMANHO      memoria total do historico (padrao 8M)");
	puts("  --max-body TAMANHO        bytes guardados por body (padrao 64K)");
	puts("  --max-headers TAMANHO     bytes guardados por headers (padrao 64K)");
	puts("  --max-transactions N      numero maximo de transacoes (padrao 2048)");
	puts("  --max-connections N       numero maximo de conexoes (padrao 512)");
	puts("  -h, --help                mostra esta ajuda");
	puts("  -V, --version             mostra a versao");
}

static void
config_reset(void)
{
	insecure_upstream = 0;
	passthrough_count = 0;
	memset(passthrough, 0, sizeof(passthrough));
	capture_limits.global_bytes = CAPTURE_DEFAULT_GLOBAL_BYTES;
	capture_limits.body_bytes = CAPTURE_DEFAULT_BODY_BYTES;
	capture_limits.header_bytes = CAPTURE_DEFAULT_HEADER_BYTES;
	capture_limits.max_transactions = CAPTURE_DEFAULT_TRANSACTIONS;
	capture_limits.max_connections = CAPTURE_DEFAULT_CONNECTIONS;
}

/* Aceita bytes puros ou um unico sufixo binario K, M ou G. */
static int
parse_size(const char *text, size_t *result)
{
	char *end;
	unsigned long long multiplier, value;

	if (text == NULL || *text == '\0' || *text == '-')
		return -1;
	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno == ERANGE || end == text || value == 0)
		return -1;
	multiplier = 1;
	if (*end != '\0') {
		if (end[1] != '\0')
			return -1;
		switch (*end) {
		case 'k':
		case 'K':
			multiplier = 1024ULL;
			break;
		case 'm':
		case 'M':
			multiplier = 1024ULL * 1024ULL;
			break;
		case 'g':
		case 'G':
			multiplier = 1024ULL * 1024ULL * 1024ULL;
			break;
		default:
			return -1;
		}
	}
	if (value > (unsigned long long)SIZE_MAX / multiplier)
		return -1;
	*result = (size_t)(value * multiplier);
	return 0;
}

static int
parse_count(const char *text, size_t *result)
{
	char *end;
	unsigned long long value;

	if (text == NULL || *text == '\0' || *text == '-')
		return -1;
	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno == ERANGE || end == text || *end != '\0' || value == 0 ||
	    value > (unsigned long long)SIZE_MAX)
		return -1;
	*result = (size_t)value;
	return 0;
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
	config_reset();
	*mode = APP_RUN;
	if (argc == 2 && (strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0)) {
		*mode = APP_HELP;
		return 0;
	}
	if (argc == 2 && (strcmp(argv[1], "-V") == 0 ||
	    strcmp(argv[1], "--version") == 0)) {
		*mode = APP_VERSION;
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
		} else if (strcmp(argv[i], "--max-memory") == 0) {
			if (++i == argc || parse_size(argv[i],
			    &capture_limits.global_bytes) == -1)
				return -1;
		} else if (strcmp(argv[i], "--max-body") == 0) {
			if (++i == argc || parse_size(argv[i],
			    &capture_limits.body_bytes) == -1)
				return -1;
		} else if (strcmp(argv[i], "--max-headers") == 0) {
			if (++i == argc || parse_size(argv[i],
			    &capture_limits.header_bytes) == -1)
				return -1;
		} else if (strcmp(argv[i], "--max-transactions") == 0) {
			if (++i == argc || parse_count(argv[i],
			    &capture_limits.max_transactions) == -1)
				return -1;
		} else if (strcmp(argv[i], "--max-connections") == 0) {
			if (++i == argc || parse_count(argv[i],
			    &capture_limits.max_connections) == -1)
				return -1;
		} else {
			return -1;
		}
	}
	return 0;
}

const struct capture_limits *
config_capture_limits(void)
{
	return &capture_limits;
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
