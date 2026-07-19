#include "muninn.h"

#include <openssl/x509v3.h>

#include <stdarg.h>
#include <stdio.h>

volatile sig_atomic_t running = 1;
static int failures;

/* Stubs: este teste exercita construcao X509, nao sockets nem ncurses. */
void
log_add(enum side side, const char *fmt, ...)
{
	(void)side;
	(void)fmt;
}

long long
monotonic_ms(void)
{
	return 0;
}

int
wait_fd_until(int fd, short events, long long deadline)
{
	(void)fd;
	(void)events;
	(void)deadline;
	return -1;
}

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: falhou: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

int
main(void)
{
	const ASN1_INTEGER *serial_a, *serial_b;
	SSL_CTX *client, *first, *second, *third;
	X509 *cert_a, *cert_b;

	CHECK(load_or_create_ca() == 0);
	client = make_client_ctx();
	CHECK(client != NULL);
	if (client != NULL)
		CHECK((SSL_CTX_get_verify_mode(client) & SSL_VERIFY_PEER) != 0);

	first = make_server_ctx_for_host("cache.example");
	second = make_server_ctx_for_host("cache.example");
	third = make_server_ctx_for_host("other.example");
	CHECK(first != NULL);
	CHECK(second != NULL);
	CHECK(third != NULL);
	CHECK(first == second);
	CHECK(first != third);

	cert_a = first == NULL ? NULL : SSL_CTX_get0_certificate(first);
	cert_b = third == NULL ? NULL : SSL_CTX_get0_certificate(third);
	CHECK(cert_a != NULL);
	CHECK(cert_b != NULL);
	if (cert_a != NULL)
		CHECK(X509_check_host(cert_a, "cache.example", 0,
		    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL) == 1);
	if (cert_a != NULL && cert_b != NULL) {
		serial_a = X509_get0_serialNumber(cert_a);
		serial_b = X509_get0_serialNumber(cert_b);
		CHECK(ASN1_INTEGER_cmp(serial_a, serial_b) != 0);
		CHECK(ASN1_STRING_length((const ASN1_STRING *)serial_a) >= 16);
	}

	SSL_CTX_free(client);
	SSL_CTX_free(first);
	SSL_CTX_free(second);
	SSL_CTX_free(third);
	tls_cleanup();
	if (failures != 0)
		return 1;
	puts("tls_test: ok");
	return 0;
}
