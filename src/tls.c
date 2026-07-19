#include "muninn.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define CERT_CACHE_MAX 256

static const unsigned char alpn_http11[] = {
	8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

struct cert_cache_entry {
	char host[256];
	SSL_CTX *ctx;
	unsigned long long used;
};

static EVP_PKEY *ca_key;
static X509 *ca_cert;
static struct cert_cache_entry cert_cache[CERT_CACHE_MAX];
static pthread_mutex_t cert_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long cert_cache_clock;

/* ------------------------------------------------------------------------- */
/* Chaves, seriais e extensoes X509                                           */
/* ------------------------------------------------------------------------- */

static EVP_PKEY *
generate_rsa_key(int bits)
{
	return EVP_RSA_gen((unsigned int)bits);
}

/*
 * Um serial X509 deve ser positivo e unico. Usamos 159 bits aleatorios: o bit
 * mais alto e limpo para o ASN.1 nao interpretar o numero como negativo.
 */
static int
set_random_serial(X509 *cert)
{
	ASN1_INTEGER *serial;
	BIGNUM *number;
	unsigned char bytes[20];
	int ok;

	if (RAND_bytes(bytes, sizeof(bytes)) != 1)
		return -1;
	bytes[0] &= 0x7f;
	if (bytes[0] == 0)
		bytes[0] = 1;
	number = BN_bin2bn(bytes, sizeof(bytes), NULL);
	if (number == NULL)
		return -1;
	serial = X509_get_serialNumber(cert);
	ok = BN_to_ASN1_INTEGER(number, serial) != NULL;
	BN_free(number);
	return ok ? 0 : -1;
}

static int
add_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX ctx;
	X509_EXTENSION *ext;
	int ok;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
	ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
	if (ext == NULL)
		return -1;
	ok = X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return ok == 1 ? 0 : -1;
}

static X509 *
generate_ca_cert(EVP_PKEY *key)
{
	X509 *cert;
	X509_NAME *name;

	cert = X509_new();
	if (cert == NULL)
		return NULL;
	if (X509_set_version(cert, 2) != 1 || set_random_serial(cert) == -1 ||
	    X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL ||
	    X509_gmtime_adj(X509_get_notAfter(cert),
	    60L * 60L * 24L * 3650L) == NULL ||
	    X509_set_pubkey(cert, key) != 1)
		goto fail;

	name = X509_get_subject_name(cert);
	if (name == NULL || X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (unsigned char *)"Muninn Local CA", -1, -1, 0) != 1 ||
	    X509_set_issuer_name(cert, name) != 1)
		goto fail;

	if (add_ext(cert, cert, NID_basic_constraints,
	    "critical,CA:TRUE,pathlen:0") == -1 ||
	    add_ext(cert, cert, NID_key_usage,
	    "critical,keyCertSign,cRLSign") == -1 ||
	    add_ext(cert, cert, NID_subject_key_identifier, "hash") == -1 ||
	    add_ext(cert, cert, NID_authority_key_identifier,
	    "keyid:always") == -1 ||
	    X509_sign(cert, key, EVP_sha256()) == 0)
		goto fail;
	return cert;

fail:
	X509_free(cert);
	return NULL;
}

static int
is_ip_address(const char *host)
{
	unsigned char buf[sizeof(struct in6_addr)];

	return inet_pton(AF_INET, host, buf) == 1 ||
	    inet_pton(AF_INET6, host, buf) == 1;
}

static X509 *
generate_leaf_cert(const char *host, EVP_PKEY *leaf_key)
{
	X509 *cert;
	X509_NAME *name;
	char san[512];

	cert = X509_new();
	if (cert == NULL)
		return NULL;
	if (X509_set_version(cert, 2) != 1 || set_random_serial(cert) == -1 ||
	    X509_gmtime_adj(X509_get_notBefore(cert), -300) == NULL ||
	    X509_gmtime_adj(X509_get_notAfter(cert),
	    60L * 60L * 24L * 397L) == NULL ||
	    X509_set_pubkey(cert, leaf_key) != 1)
		goto fail;

	name = X509_get_subject_name(cert);
	if (name == NULL || X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (unsigned char *)host, -1, -1, 0) != 1 ||
	    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert)) != 1)
		goto fail;

	snprintf(san, sizeof(san), "%s:%s", is_ip_address(host) ? "IP" : "DNS",
	    host);
	if (add_ext(cert, ca_cert, NID_basic_constraints,
	    "critical,CA:FALSE") == -1 ||
	    add_ext(cert, ca_cert, NID_key_usage,
	    "critical,digitalSignature,keyEncipherment") == -1 ||
	    add_ext(cert, ca_cert, NID_ext_key_usage, "serverAuth") == -1 ||
	    add_ext(cert, ca_cert, NID_subject_key_identifier, "hash") == -1 ||
	    add_ext(cert, ca_cert, NID_authority_key_identifier,
	    "keyid:always") == -1 ||
	    add_ext(cert, ca_cert, NID_subject_alt_name, san) == -1 ||
	    X509_sign(cert, ca_key, EVP_sha256()) == 0)
		goto fail;
	return cert;

fail:
	X509_free(cert);
	return NULL;
}

/* ------------------------------------------------------------------------- */
/* Arquivos da CA                                                             */
/* ------------------------------------------------------------------------- */

static EVP_PKEY *
read_private_key(const char *path)
{
	EVP_PKEY *key;
	FILE *fp;

	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;
	key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return key;
}

static X509 *
read_cert(const char *path)
{
	X509 *cert;
	FILE *fp;

	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	return cert;
}

static int
regular_file_state(const char *path)
{
	struct stat st;

	if (lstat(path, &st) == -1)
		return errno == ENOENT ? 0 : -1;
	return S_ISREG(st.st_mode) ? 1 : -1;
}

/*
 * Escreve primeiro em um arquivo exclusivo no mesmo diretorio. link(2)
 * publica o PEM completo sem substituir um destino que ja exista; depois
 * removemos o nome temporario.
 */
static int
write_key_atomic(const char *path, EVP_PKEY *key)
{
	char temporary[512];
	FILE *fp;
	int fd, ok;

	snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
	    (long)getpid());
	fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1)
		return -1;
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		close(fd);
		unlink(temporary);
		return -1;
	}
	ok = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) == 1;
	if (ok && fflush(fp) != 0)
		ok = 0;
	if (ok && fsync(fd) != 0)
		ok = 0;
	if (fclose(fp) != 0)
		ok = 0;
	if (!ok || link(temporary, path) == -1) {
		unlink(temporary);
		return -1;
	}
	unlink(temporary);
	return chmod(path, 0600);
}

static int
write_cert_atomic(const char *path, X509 *cert)
{
	char temporary[512];
	FILE *fp;
	int fd, ok;

	snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
	    (long)getpid());
	fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd == -1)
		return -1;
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		close(fd);
		unlink(temporary);
		return -1;
	}
	ok = PEM_write_X509(fp, cert) == 1;
	if (ok && fflush(fp) != 0)
		ok = 0;
	if (ok && fsync(fd) != 0)
		ok = 0;
	if (fclose(fp) != 0)
		ok = 0;
	if (!ok || link(temporary, path) == -1) {
		unlink(temporary);
		return -1;
	}
	unlink(temporary);
	return chmod(path, 0644);
}

static int
validate_ca_pair(EVP_PKEY *key, X509 *cert)
{
	if (key == NULL || cert == NULL ||
	    X509_check_private_key(cert, key) != 1 ||
	    X509_check_ca(cert) <= 0 ||
	    X509_verify(cert, key) != 1 ||
	    X509_cmp_current_time(X509_get0_notBefore(cert)) >= 0 ||
	    X509_cmp_current_time(X509_get0_notAfter(cert)) <= 0)
		return -1;
	return 0;
}

static int
load_existing_ca(void)
{
	EVP_PKEY *key;
	X509 *cert;

	key = read_private_key(CA_KEY_FILE);
	cert = read_cert(CA_CERT_FILE);
	if (validate_ca_pair(key, cert) == -1) {
		EVP_PKEY_free(key);
		X509_free(cert);
		return -1;
	}
	if (chmod(CA_KEY_FILE, 0600) == -1) {
		EVP_PKEY_free(key);
		X509_free(cert);
		return -1;
	}
	EVP_PKEY_free(ca_key);
	X509_free(ca_cert);
	ca_key = key;
	ca_cert = cert;
	return 0;
}

static int
create_ca(void)
{
	EVP_PKEY *key;
	X509 *cert;
	int key_state, cert_state;

	key_state = regular_file_state(CA_KEY_FILE);
	cert_state = regular_file_state(CA_CERT_FILE);
	if (key_state != 0 || cert_state != 0)
		return -1;

	key = generate_rsa_key(3072);
	cert = key == NULL ? NULL : generate_ca_cert(key);
	if (key == NULL || cert == NULL)
		goto fail;
	if (write_key_atomic(CA_KEY_FILE, key) == -1)
		goto fail;
	if (write_cert_atomic(CA_CERT_FILE, cert) == -1) {
		unlink(CA_KEY_FILE);
		goto fail;
	}

	ca_key = key;
	ca_cert = cert;
	return 0;

fail:
	EVP_PKEY_free(key);
	X509_free(cert);
	return -1;
}

int
load_or_create_ca(void)
{
	int key_state, cert_state;

	key_state = regular_file_state(CA_KEY_FILE);
	cert_state = regular_file_state(CA_CERT_FILE);
	if (key_state == 1 && cert_state == 1) {
		if (load_existing_ca() == -1)
			return -1;
		log_add(SIDE_C2S, "CA validada: %s (chave 0600)", CA_CERT_FILE);
		return 0;
	}
	if (key_state != 0 || cert_state != 0)
		return -1;
	if (create_ca() == -1)
		return -1;
	log_add(SIDE_C2S, "CA criada: importe %s no navegador", CA_CERT_FILE);
	return 0;
}

int
tls_ca_create_command(void)
{
	if (load_or_create_ca() == -1) {
		fprintf(stderr, "CA ausente, incompleta ou invalida; arquivos preservados\n");
		return -1;
	}
	printf("CA pronta: %s\nChave privada: %s (0600)\n", CA_CERT_FILE,
	    CA_KEY_FILE);
	return 0;
}

int
tls_ca_show_command(void)
{
	if (regular_file_state(CA_KEY_FILE) != 1 ||
	    regular_file_state(CA_CERT_FILE) != 1 ||
	    load_existing_ca() == -1) {
		fprintf(stderr, "CA nao encontrada ou invalida\n");
		return -1;
	}
	return X509_print_fp(stdout, ca_cert) == 1 ? 0 : -1;
}

int
tls_ca_fingerprint_command(void)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int len, i;

	if (regular_file_state(CA_KEY_FILE) != 1 ||
	    regular_file_state(CA_CERT_FILE) != 1 ||
	    load_existing_ca() == -1 ||
	    X509_digest(ca_cert, EVP_sha256(), digest, &len) != 1) {
		fprintf(stderr, "CA nao encontrada ou invalida\n");
		return -1;
	}
	fputs("SHA256 Fingerprint=", stdout);
	for (i = 0; i < len; i++)
		printf("%s%02X", i == 0 ? "" : ":", digest[i]);
	putchar('\n');
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Cache de certificados por host                                             */
/* ------------------------------------------------------------------------- */

static int
alpn_select_http11(SSL *ssl, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
	unsigned int pos;

	(void)ssl;
	(void)arg;
	for (pos = 0; pos < inlen;) {
		unsigned int len = in[pos++];

		if (len > inlen - pos)
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		if (len == 8 && memcmp(in + pos, "http/1.1", 8) == 0) {
			*out = in + pos;
			*outlen = 8;
			return SSL_TLSEXT_ERR_OK;
		}
		pos += len;
	}
	/*
	 * Se o cliente anunciou ALPN mas nao aceita HTTP/1.1, continuar poderia
	 * entregar HTTP/2 binario ao parser HTTP/1.x. Falhamos explicitamente.
	 */
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *
build_server_ctx(const char *host)
{
	EVP_PKEY *leaf_key;
	SSL_CTX *ctx;
	X509 *leaf_cert;

	ctx = SSL_CTX_new(TLS_server_method());
	leaf_key = NULL;
	leaf_cert = NULL;
	if (ctx == NULL ||
	    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
		goto fail;
	SSL_CTX_set_alpn_select_cb(ctx, alpn_select_http11, NULL);

	leaf_key = generate_rsa_key(2048);
	leaf_cert = leaf_key == NULL ? NULL : generate_leaf_cert(host, leaf_key);
	if (leaf_key == NULL || leaf_cert == NULL ||
	    SSL_CTX_use_PrivateKey(ctx, leaf_key) != 1 ||
	    SSL_CTX_use_certificate(ctx, leaf_cert) != 1 ||
	    SSL_CTX_check_private_key(ctx) != 1)
		goto fail;

	EVP_PKEY_free(leaf_key);
	X509_free(leaf_cert);
	return ctx;

fail:
	EVP_PKEY_free(leaf_key);
	X509_free(leaf_cert);
	SSL_CTX_free(ctx);
	return NULL;
}

SSL_CTX *
make_server_ctx_for_host(const char *host)
{
	SSL_CTX *built, *result;
	size_t empty, i, oldest;
	unsigned long long oldest_used;

	pthread_mutex_lock(&cert_cache_lock);
	for (i = 0; i < CERT_CACHE_MAX; i++) {
		if (cert_cache[i].ctx != NULL &&
		    strcasecmp(cert_cache[i].host, host) == 0) {
			cert_cache[i].used = ++cert_cache_clock;
			SSL_CTX_up_ref(cert_cache[i].ctx);
			result = cert_cache[i].ctx;
			pthread_mutex_unlock(&cert_cache_lock);
			return result;
		}
	}
	pthread_mutex_unlock(&cert_cache_lock);

	/* Geracao RSA fica fora do mutex para nao parar outros cache hits. */
	built = build_server_ctx(host);
	if (built == NULL)
		return NULL;

	pthread_mutex_lock(&cert_cache_lock);
	for (i = 0; i < CERT_CACHE_MAX; i++) {
		if (cert_cache[i].ctx != NULL &&
		    strcasecmp(cert_cache[i].host, host) == 0) {
			SSL_CTX_up_ref(cert_cache[i].ctx);
			result = cert_cache[i].ctx;
			cert_cache[i].used = ++cert_cache_clock;
			pthread_mutex_unlock(&cert_cache_lock);
			SSL_CTX_free(built);
			return result;
		}
	}

	empty = CERT_CACHE_MAX;
	oldest = 0;
	oldest_used = ~0ULL;
	for (i = 0; i < CERT_CACHE_MAX; i++) {
		if (cert_cache[i].ctx == NULL) {
			empty = i;
			break;
		}
		if (cert_cache[i].used < oldest_used) {
			oldest = i;
			oldest_used = cert_cache[i].used;
		}
	}
	i = empty != CERT_CACHE_MAX ? empty : oldest;
	SSL_CTX_free(cert_cache[i].ctx);
	snprintf(cert_cache[i].host, sizeof(cert_cache[i].host), "%s", host);
	cert_cache[i].ctx = built;
	cert_cache[i].used = ++cert_cache_clock;
	SSL_CTX_up_ref(built);
	pthread_mutex_unlock(&cert_cache_lock);
	return built;
}

/* ------------------------------------------------------------------------- */
/* TLS upstream, handshake e diagnostico                                      */
/* ------------------------------------------------------------------------- */

SSL_CTX *
make_client_ctx(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL ||
	    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
		goto fail;
	if (config_insecure_upstream()) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		if (SSL_CTX_set_default_verify_paths(ctx) != 1)
			goto fail;
	}
	return ctx;

fail:
	SSL_CTX_free(ctx);
	return NULL;
}

int
tls_configure_upstream(SSL *ssl, const char *host)
{
	X509_VERIFY_PARAM *param;

	if (SSL_set_alpn_protos(ssl, alpn_http11, sizeof(alpn_http11)) != 0)
		return -1;
	param = SSL_get0_param(ssl);
	if (param == NULL)
		return -1;
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if (is_ip_address(host))
		return X509_VERIFY_PARAM_set1_ip_asc(param, host) == 1 ? 0 : -1;
	if (SSL_set_tlsext_host_name(ssl, host) != 1 ||
	    SSL_set1_host(ssl, host) != 1)
		return -1;
	return 0;
}

int
tls_handshake(SSL *ssl, int accept_side, int timeout_ms)
{
	long long deadline;
	int error, fd, n, ready;
	short event;

	fd = SSL_get_fd(ssl);
	if (fd == -1)
		return -1;
	deadline = monotonic_ms() + timeout_ms;

	for (;;) {
		n = accept_side ? SSL_accept(ssl) : SSL_connect(ssl);
		if (n == 1)
			return 0;
		error = SSL_get_error(ssl, n);
		if (error == SSL_ERROR_WANT_READ)
			event = POLLIN;
		else if (error == SSL_ERROR_WANT_WRITE)
			event = POLLOUT;
		else
			return -1;
		ready = wait_fd_until(fd, event, deadline);
		if (ready <= 0 || (ready & (POLLERR | POLLNVAL)))
			return -1;
	}
}

void
tls_log_errors(enum side side, int id, const char *context)
{
	char detail[160];
	unsigned long error;
	int count;

	count = 0;
	while ((error = ERR_get_error()) != 0 && count < 3) {
		ERR_error_string_n(error, detail, sizeof(detail));
		log_add(side, "#%d %s: %s", id, context, detail);
		count++;
	}
	if (count == 0)
		log_add(side, "#%d %s: sem detalhe OpenSSL", id, context);
}

void
tls_log_session(enum side side, int id, const char *label, SSL *ssl,
    int show_verify)
{
	const unsigned char *alpn;
	const char *cipher, *version;
	unsigned int alpn_len;
	long verify;

	version = SSL_get_version(ssl);
	cipher = SSL_get_cipher_name(ssl);
	SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
	if (alpn_len == 0) {
		alpn = (const unsigned char *)"(nenhum)";
		alpn_len = 8;
	}
	log_add(side, "#%d %s: %s %s ALPN=%.*s", id, label,
	    version == NULL ? "TLS?" : version,
	    cipher == NULL ? "cipher?" : cipher, (int)alpn_len, alpn);
	if (!show_verify)
		return;
	if (config_insecure_upstream()) {
		log_add(side, "#%d upstream certificado: verificacao DESATIVADA",
		    id);
		return;
	}
	verify = SSL_get_verify_result(ssl);
	log_add(side, "#%d upstream certificado: %s", id,
	    verify == X509_V_OK ? "verificado" :
	    X509_verify_cert_error_string(verify));
}

void
tls_cleanup(void)
{
	size_t i;

	pthread_mutex_lock(&cert_cache_lock);
	for (i = 0; i < CERT_CACHE_MAX; i++) {
		SSL_CTX_free(cert_cache[i].ctx);
		cert_cache[i].ctx = NULL;
		cert_cache[i].host[0] = '\0';
	}
	pthread_mutex_unlock(&cert_cache_lock);
	X509_free(ca_cert);
	EVP_PKEY_free(ca_key);
	ca_cert = NULL;
	ca_key = NULL;
}
