#define _POSIX_C_SOURCE 200112L

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <ctype.h>
#include <curses.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/*
 * Muninn e um proxy HTTP/HTTPS pequeno, feito para ser lido.
 *
 * A ideia e parecida com o Burp no caminho HTTPS:
 *
 *   navegador -> Muninn -> servidor real
 *
 * Para HTTP puro, Muninn so conecta no servidor e copia bytes.
 * Para HTTPS, o navegador manda CONNECT host:443. Muninn responde 200,
 * cria um certificado falso para esse host assinado pela CA local de Muninn,
 * termina o TLS do navegador, abre outro TLS ate o servidor real e copia os
 * dados descriptografados entre os dois lados.
 *
 * Este arquivo usa threads bloqueantes de proposito. OpenSSL nao-bloqueante e
 * possivel, mas mistura SSL_ERROR_WANT_READ/WRITE com o loop de eventos e deixa
 * o primeiro MITM bem mais dificil de estudar. Aqui cada conexao fica isolada
 * em uma thread, e cada direcao do fluxo fica em uma thread de relay.
 */

#define LISTEN_HOST "127.0.0.1"
#define LISTEN_PORT "13337"
#define BACKLOG 128

#define HEADER_MAX 65536
#define RELAY_BUF 8192

#define LOG_LINES 1024
#define LOG_LINE 240

#define CA_KEY_FILE "muninn-ca-key.pem"
#define CA_CERT_FILE "muninn-ca-cert.pem"

enum side {
	SIDE_C2S = 0, /* client -> server: navegador indo para fora */
	SIDE_S2C = 1  /* server -> client: servidor voltando ao navegador */
};

struct logbuf {
	char line[LOG_LINES][LOG_LINE];
	int count;
	int start;
};

struct request {
	char method[32];
	char target[1024];
	char version[32];
	char host[256];
	char port[16];
	unsigned char raw[HEADER_MAX];
	size_t raw_len;
};

struct relay {
	int id;
	enum side side;
	int use_ssl;
	int from_fd;
	int to_fd;
	SSL *from_ssl;
	SSL *to_ssl;
};

static struct logbuf logs[2];
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t id_lock = PTHREAD_MUTEX_INITIALIZER;
static int next_id = 1;
static int active_tab = SIDE_C2S;
static volatile sig_atomic_t running = 1;

static EVP_PKEY *ca_key;
static X509 *ca_cert;

/* ------------------------------------------------------------------------- */
/* Utilitarios pequenos                                                       */
/* ------------------------------------------------------------------------- */

static void
die(const char *msg)
{
	perror(msg);
	exit(1);
}

static void
on_signal(int signo)
{
	(void)signo;
	running = 0;
}

static int
new_conn_id(void)
{
	int id;

	pthread_mutex_lock(&id_lock);
	id = next_id++;
	pthread_mutex_unlock(&id_lock);
	return id;
}

static void
close_fd(int *fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

static int
set_reuseaddr(int fd)
{
	int yes = 1;

	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

/* ------------------------------------------------------------------------- */
/* Log e TUI                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * O log e um ring buffer simples por aba. A TUI le esse buffer enquanto as
 * threads de rede escrevem nele, entao protegemos tudo com um mutex.
 */
static void
log_add(enum side side, const char *fmt, ...)
{
	struct logbuf *l = &logs[side];
	struct timeval tv;
	struct tm tm;
	char msg[LOG_LINE - 48];
	char stamp[32];
	va_list ap;
	int idx;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(stamp, sizeof(stamp), "%H:%M:%S", &tm);

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	pthread_mutex_lock(&log_lock);
	if (l->count < LOG_LINES) {
		idx = (l->start + l->count) % LOG_LINES;
		l->count++;
	} else {
		idx = l->start;
		l->start = (l->start + 1) % LOG_LINES;
	}
	snprintf(l->line[idx], LOG_LINE, "%s.%03ld %.180s", stamp,
	    (long)(tv.tv_usec / 1000), msg);
	pthread_mutex_unlock(&log_lock);
}

/*
 * Mostra bytes como texto quando possivel, e escapa o resto. Isso nao tenta ser
 * um parser HTTP completo; e so uma visao rapida do trafego que passou.
 */
static void
log_bytes(enum side side, int id, const unsigned char *buf, size_t len)
{
	char out[LOG_LINE];
	size_t i, pos;

	pos = snprintf(out, sizeof(out), "#%d %zu bytes: ", id, len);
	for (i = 0; i < len && pos + 5 < sizeof(out); i++) {
		unsigned char c = buf[i];

		if (c == '\r') {
			out[pos++] = '\\';
			out[pos++] = 'r';
		} else if (c == '\n') {
			out[pos++] = '\\';
			out[pos++] = 'n';
			out[pos++] = ' ';
		} else if (isprint(c) || c == '\t') {
			out[pos++] = (char)c;
		} else {
			pos += snprintf(out + pos, sizeof(out) - pos, "\\x%02x", c);
		}
	}
	if (i < len && pos + 4 < sizeof(out)) {
		out[pos++] = '.';
		out[pos++] = '.';
		out[pos++] = '.';
	}
	out[pos] = '\0';
	log_add(side, "%s", out);
}

static void
tui_init(void)
{
	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	curs_set(0);

	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(1, COLOR_BLACK, COLOR_CYAN);
		init_pair(2, COLOR_CYAN, -1);
	}
}

static void
tui_input(void)
{
	int ch;

	while ((ch = getch()) != ERR) {
		if (ch == 'q' || ch == 'Q')
			running = 0;
		else if (ch == '\t' || ch == KEY_LEFT || ch == KEY_RIGHT)
			active_tab = active_tab == SIDE_C2S ? SIDE_S2C : SIDE_C2S;
	}
}

static void
tui_draw(void)
{
	char copy[LOG_LINES][LOG_LINE];
	struct logbuf *l = &logs[active_tab];
	int rows, cols, i, n, idx, first, count;

	getmaxyx(stdscr, rows, cols);
	erase();

	if (has_colors())
		attron(COLOR_PAIR(active_tab == SIDE_C2S ? 1 : 2));
	mvaddnstr(0, 0, " C->S ", cols);
	if (has_colors()) {
		attroff(COLOR_PAIR(active_tab == SIDE_C2S ? 1 : 2));
		attron(COLOR_PAIR(active_tab == SIDE_S2C ? 1 : 2));
	}
	mvaddnstr(0, 7, " S->C ", cols - 7);
	if (has_colors())
		attroff(COLOR_PAIR(active_tab == SIDE_S2C ? 1 : 2));
	mvprintw(0, 16, " %s:%s  tab troca  q sai  CA: %s",
	    LISTEN_HOST, LISTEN_PORT, CA_CERT_FILE);
	mvhline(1, 0, ACS_HLINE, cols);

	n = rows - 3;
	if (n < 1) {
		refresh();
		return;
	}

	/*
	 * Copiamos as linhas para uma area local e soltamos o mutex antes de
	 * desenhar. Assim a TUI nao segura as threads de rede por muito tempo.
	 */
	pthread_mutex_lock(&log_lock);
	count = l->count;
	first = count > n ? count - n : 0;
	for (i = 0; i < n && first + i < count; i++) {
		idx = (l->start + first + i) % LOG_LINES;
		snprintf(copy[i], sizeof(copy[i]), "%s", l->line[idx]);
	}
	pthread_mutex_unlock(&log_lock);

	for (i = 0; i < n && first + i < count; i++)
		mvaddnstr(2 + i, 0, copy[i], cols - 1);
	refresh();
}

/* ------------------------------------------------------------------------- */
/* Sockets                                                                    */
/* ------------------------------------------------------------------------- */

static int
listen_socket(void)
{
	struct addrinfo hints, *res, *ai;
	int fd = -1, error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(LISTEN_HOST, LISTEN_PORT, &hints, &res);
	if (error != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		exit(1);
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd == -1)
			continue;
		set_reuseaddr(fd);
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);

	if (fd == -1)
		die("bind");
	if (listen(fd, BACKLOG) == -1)
		die("listen");
	return fd;
}

static int
connect_host(const char *host, const char *port)
{
	struct addrinfo hints, *res, *ai;
	int fd = -1, error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error = getaddrinfo(host, port, &hints, &res);
	if (error != 0)
		return -1;

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd == -1)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

/* ------------------------------------------------------------------------- */
/* Parser HTTP minimo                                                         */
/* ------------------------------------------------------------------------- */

static char *
header_end(unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 3; i < len; i++) {
		if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
		    buf[i - 1] == '\r' && buf[i] == '\n')
			return (char *)&buf[i + 1];
	}
	for (i = 1; i < len; i++) {
		if (buf[i - 1] == '\n' && buf[i] == '\n')
			return (char *)&buf[i + 1];
	}
	return NULL;
}

static void
trim(char *s)
{
	char *p;

	while (*s && isspace((unsigned char)*s))
		memmove(s, s + 1, strlen(s));
	p = s + strlen(s);
	while (p > s && isspace((unsigned char)p[-1]))
		*--p = '\0';
}

static int
read_http_header(int fd, struct request *req)
{
	ssize_t n;

	memset(req, 0, sizeof(*req));
	while (req->raw_len < sizeof(req->raw)) {
		n = recv(fd, req->raw + req->raw_len,
		    sizeof(req->raw) - req->raw_len, 0);
		if (n <= 0)
			return -1;
		req->raw_len += (size_t)n;
		if (header_end(req->raw, req->raw_len) != NULL)
			return 0;
	}
	return -1;
}

static int
parse_first_line(struct request *req)
{
	char tmp[HEADER_MAX + 1], *eol;
	size_t n;

	memcpy(tmp, req->raw, req->raw_len);
	tmp[req->raw_len] = '\0';
	eol = strstr(tmp, "\r\n");
	if (eol == NULL)
		eol = strchr(tmp, '\n');
	if (eol == NULL)
		return -1;
	*eol = '\0';

	n = sscanf(tmp, "%31s %1023s %31s", req->method, req->target,
	    req->version);
	return n == 3 ? 0 : -1;
}

static int
parse_host_header(struct request *req)
{
	char tmp[HEADER_MAX + 1], *line, *saveptr, *v, *colon;

	memcpy(tmp, req->raw, req->raw_len);
	tmp[req->raw_len] = '\0';

	for (line = strtok_r(tmp, "\n", &saveptr); line != NULL;
	    line = strtok_r(NULL, "\n", &saveptr)) {
		if (strncasecmp(line, "Host:", 5) != 0)
			continue;
		v = line + 5;
		trim(v);
		colon = strrchr(v, ':');
		if (colon != NULL && strchr(colon + 1, ']') == NULL) {
			*colon++ = '\0';
			snprintf(req->port, sizeof(req->port), "%s", colon);
		} else {
			snprintf(req->port, sizeof(req->port), "80");
		}
		if (v[0] == '[') {
			v++;
			colon = strchr(v, ']');
			if (colon != NULL)
				*colon = '\0';
		}
		snprintf(req->host, sizeof(req->host), "%s", v);
		return 0;
	}
	return -1;
}

static int
parse_connect_target(struct request *req)
{
	char target[sizeof(req->target)], *host, *port, *end;

	snprintf(target, sizeof(target), "%s", req->target);
	host = target;
	if (host[0] == '[') {
		host++;
		end = strchr(host, ']');
		if (end == NULL)
			return -1;
		*end++ = '\0';
		port = *end == ':' ? end + 1 : "443";
	} else {
		port = strrchr(host, ':');
		if (port != NULL)
			*port++ = '\0';
		else
			port = "443";
	}
	if (host[0] == '\0' || port[0] == '\0')
		return -1;
	if (strlen(host) >= sizeof(req->host) || strlen(port) >= sizeof(req->port))
		return -1;
	strcpy(req->host, host);
	strcpy(req->port, port);
	return 0;
}

/*
 * Browsers mandam requests HTTP para proxy no formato absoluto:
 *   GET http://example.com/path HTTP/1.1
 *
 * Servidores normais esperam so o path:
 *   GET /path HTTP/1.1
 *
 * Esta funcao reescreve so a primeira linha. Os headers seguem iguais.
 */
static int
make_origin_request(struct request *req, unsigned char *out, size_t outsz,
    size_t *outlen)
{
	char tmp[HEADER_MAX + 1], *headers, *path;
	int n;

	memcpy(tmp, req->raw, req->raw_len);
	tmp[req->raw_len] = '\0';
	headers = strstr(tmp, "\r\n");
	if (headers == NULL)
		headers = strchr(tmp, '\n');
	if (headers == NULL)
		return -1;

	if (strncmp(req->target, "http://", 7) == 0) {
		path = strchr(req->target + 7, '/');
		if (path == NULL)
			path = "/";
	} else {
		path = req->target;
	}

	n = snprintf((char *)out, outsz, "%s %s %s%s", req->method, path,
	    req->version, headers);
	if (n < 0 || (size_t)n >= outsz)
		return -1;
	*outlen = (size_t)n;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* CA local e certificados dinamicos                                          */
/* ------------------------------------------------------------------------- */

static EVP_PKEY *
generate_rsa_key(void)
{
	EVP_PKEY *key;

	/*
	 * EVP_RSA_gen existe no OpenSSL 3 e evita as APIs RSA_* antigas.
	 * O retorno ja e um EVP_PKEY pronto para X509_sign/SSL_CTX_use_*.
	 */
	key = EVP_RSA_gen(2048);
	return key;
}

static int
write_private_key(const char *path, EVP_PKEY *key)
{
	FILE *fp;
	int ok;

	fp = fopen(path, "w");
	if (fp == NULL)
		return -1;
	ok = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
	fclose(fp);
	return ok == 1 ? 0 : -1;
}

static int
write_cert(const char *path, X509 *cert)
{
	FILE *fp;
	int ok;

	fp = fopen(path, "w");
	if (fp == NULL)
		return -1;
	ok = PEM_write_X509(fp, cert);
	fclose(fp);
	return ok == 1 ? 0 : -1;
}

static EVP_PKEY *
read_private_key(const char *path)
{
	FILE *fp;
	EVP_PKEY *key;

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
	FILE *fp;
	X509 *cert;

	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	return cert;
}

static int
add_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX ctx;
	X509_EXTENSION *ext;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
	ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
	if (ext == NULL)
		return -1;
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return 0;
}

static X509 *
generate_ca_cert(EVP_PKEY *key)
{
	X509 *cert;
	X509_NAME *name;
	unsigned char serial[16];

	cert = X509_new();
	if (cert == NULL)
		return NULL;

	RAND_bytes(serial, sizeof(serial));
	ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert), 1);
	X509_set_version(cert, 2);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * 3650L);
	X509_set_pubkey(cert, key);

	name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	    (unsigned char *)"Muninn Local CA", -1, -1, 0);
	X509_set_issuer_name(cert, name);

	add_ext(cert, cert, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign");
	add_ext(cert, cert, NID_subject_key_identifier, "hash");

	if (X509_sign(cert, key, EVP_sha256()) == 0) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static int
load_or_create_ca(void)
{
	ca_key = read_private_key(CA_KEY_FILE);
	ca_cert = read_cert(CA_CERT_FILE);
	if (ca_key != NULL && ca_cert != NULL) {
		log_add(SIDE_C2S, "CA carregada: %s", CA_CERT_FILE);
		return 0;
	}

	EVP_PKEY_free(ca_key);
	X509_free(ca_cert);
	ca_key = generate_rsa_key();
	if (ca_key == NULL)
		return -1;
	ca_cert = generate_ca_cert(ca_key);
	if (ca_cert == NULL)
		return -1;
	if (write_private_key(CA_KEY_FILE, ca_key) == -1 ||
	    write_cert(CA_CERT_FILE, ca_cert) == -1)
		return -1;
	log_add(SIDE_C2S, "CA criada: importe %s no navegador", CA_CERT_FILE);
	return 0;
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

	ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert),
	    (uint64_t)time(NULL) ^ (uint64_t)pthread_self());
	X509_set_version(cert, 2);
	X509_gmtime_adj(X509_get_notBefore(cert), -300);
	X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * 397L);
	X509_set_pubkey(cert, leaf_key);

	name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	    (unsigned char *)host, -1, -1, 0);
	X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

	add_ext(cert, ca_cert, NID_basic_constraints, "CA:FALSE");
	add_ext(cert, ca_cert, NID_key_usage, "digitalSignature,keyEncipherment");
	add_ext(cert, ca_cert, NID_ext_key_usage, "serverAuth");

	snprintf(san, sizeof(san), "%s:%s", is_ip_address(host) ? "IP" : "DNS",
	    host);
	add_ext(cert, ca_cert, NID_subject_alt_name, san);

	if (X509_sign(cert, ca_key, EVP_sha256()) == 0) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static SSL_CTX *
make_server_ctx_for_host(const char *host)
{
	SSL_CTX *ctx;
	EVP_PKEY *leaf_key;
	X509 *leaf_cert;

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL)
		return NULL;
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	leaf_key = generate_rsa_key();
	leaf_cert = leaf_key == NULL ? NULL : generate_leaf_cert(host, leaf_key);
	if (leaf_key == NULL || leaf_cert == NULL)
		goto fail;

	if (SSL_CTX_use_PrivateKey(ctx, leaf_key) != 1 ||
	    SSL_CTX_use_certificate(ctx, leaf_cert) != 1)
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

static SSL_CTX *
make_client_ctx(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		return NULL;
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	/*
	 * Para uma primeira ferramenta local, nao bloqueamos em validacao do
	 * certificado do servidor real. Burp tambem separa "ver o trafego" de
	 * "decidir politica de confianca". Isso pode ser endurecido depois.
	 */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	return ctx;
}

/* ------------------------------------------------------------------------- */
/* Relay de dados                                                             */
/* ------------------------------------------------------------------------- */

static ssize_t
io_read(struct relay *r, unsigned char *buf, size_t len)
{
	int n;

	if (r->use_ssl) {
		n = SSL_read(r->from_ssl, buf, (int)len);
		if (n <= 0)
			return -1;
		return n;
	}
	return recv(r->from_fd, buf, len, 0);
}

static ssize_t
io_write(struct relay *r, const unsigned char *buf, size_t len)
{
	size_t off = 0;
	int n;
	ssize_t w;

	while (off < len) {
		if (r->use_ssl) {
			n = SSL_write(r->to_ssl, buf + off, (int)(len - off));
			if (n <= 0)
				return -1;
			off += (size_t)n;
		} else {
			w = send(r->to_fd, buf + off, len - off, 0);
			if (w <= 0)
				return -1;
			off += (size_t)w;
		}
	}
	return (ssize_t)off;
}

static void *
relay_thread(void *arg)
{
	struct relay *r = arg;
	unsigned char buf[RELAY_BUF];
	ssize_t n;

	for (;;) {
		n = io_read(r, buf, sizeof(buf));
		if (n <= 0)
			break;
		log_bytes(r->side, r->id, buf, (size_t)n);
		if (io_write(r, buf, (size_t)n) <= 0)
			break;
	}

	/*
	 * Quando o lado de origem acaba, tentamos avisar o destino de forma
	 * limpa. Em TLS isso manda close_notify; em TCP puro isso derruba o
	 * socket para acordar a outra thread que pode estar bloqueada.
	 */
	if (r->use_ssl && r->to_ssl != NULL)
		SSL_shutdown(r->to_ssl);
	shutdown(r->from_fd, SHUT_RDWR);
	shutdown(r->to_fd, SHUT_RDWR);
	free(r);
	return NULL;
}

static void
start_relays(int id, int client_fd, int server_fd, SSL *client_ssl,
    SSL *server_ssl, int use_ssl)
{
	pthread_t a, b;
	struct relay *c2s, *s2c;

	c2s = calloc(1, sizeof(*c2s));
	s2c = calloc(1, sizeof(*s2c));
	if (c2s == NULL || s2c == NULL)
		return;

	c2s->id = id;
	c2s->side = SIDE_C2S;
	c2s->use_ssl = use_ssl;
	c2s->from_fd = client_fd;
	c2s->to_fd = server_fd;
	c2s->from_ssl = client_ssl;
	c2s->to_ssl = server_ssl;

	s2c->id = id;
	s2c->side = SIDE_S2C;
	s2c->use_ssl = use_ssl;
	s2c->from_fd = server_fd;
	s2c->to_fd = client_fd;
	s2c->from_ssl = server_ssl;
	s2c->to_ssl = client_ssl;

	pthread_create(&a, NULL, relay_thread, c2s);
	pthread_create(&b, NULL, relay_thread, s2c);
	pthread_join(a, NULL);
	pthread_join(b, NULL);
}

/* ------------------------------------------------------------------------- */
/* Fluxos HTTP e HTTPS                                                        */
/* ------------------------------------------------------------------------- */

static void
handle_plain_http(int id, int client_fd, struct request *req)
{
	int server_fd = -1;
	unsigned char out[HEADER_MAX + 1];
	size_t outlen;

	if (parse_host_header(req) == -1 ||
	    make_origin_request(req, out, sizeof(out), &outlen) == -1) {
		log_add(SIDE_C2S, "#%d HTTP invalido", id);
		return;
	}

	log_add(SIDE_C2S, "#%d HTTP %s %s -> %s:%s", id, req->method,
	    req->target, req->host, req->port);
	log_bytes(SIDE_C2S, id, req->raw, req->raw_len);

	server_fd = connect_host(req->host, req->port);
	if (server_fd == -1) {
		log_add(SIDE_C2S, "#%d falha conectando %s:%s", id, req->host,
		    req->port);
		return;
	}
	if (send(server_fd, out, outlen, 0) <= 0) {
		close_fd(&server_fd);
		return;
	}

	start_relays(id, client_fd, server_fd, NULL, NULL, 0);
	close_fd(&server_fd);
}

static void
handle_https_mitm(int id, int client_fd, struct request *req)
{
	SSL_CTX *server_ctx = NULL, *client_ctx = NULL;
	SSL *browser_ssl = NULL, *upstream_ssl = NULL;
	int server_fd = -1;
	static const char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";

	if (parse_connect_target(req) == -1) {
		log_add(SIDE_C2S, "#%d CONNECT invalido: %s", id, req->target);
		return;
	}

	log_add(SIDE_C2S, "#%d CONNECT %s:%s", id, req->host, req->port);
	server_fd = connect_host(req->host, req->port);
	if (server_fd == -1) {
		log_add(SIDE_C2S, "#%d falha conectando upstream", id);
		return;
	}

	client_ctx = make_client_ctx();
	upstream_ssl = client_ctx == NULL ? NULL : SSL_new(client_ctx);
	if (upstream_ssl == NULL)
		goto done;
	SSL_set_fd(upstream_ssl, server_fd);
	SSL_set_tlsext_host_name(upstream_ssl, req->host);
	if (SSL_connect(upstream_ssl) != 1) {
		log_add(SIDE_C2S, "#%d TLS upstream falhou", id);
		goto done;
	}

	if (send(client_fd, ok, sizeof(ok) - 1, 0) <= 0)
		goto done;
	log_add(SIDE_S2C, "#%d 200 Connection Established", id);

	server_ctx = make_server_ctx_for_host(req->host);
	browser_ssl = server_ctx == NULL ? NULL : SSL_new(server_ctx);
	if (browser_ssl == NULL)
		goto done;
	SSL_set_fd(browser_ssl, client_fd);
	if (SSL_accept(browser_ssl) != 1) {
		log_add(SIDE_C2S, "#%d TLS navegador falhou", id);
		goto done;
	}

	log_add(SIDE_C2S, "#%d MITM ativo para %s", id, req->host);
	start_relays(id, client_fd, server_fd, browser_ssl, upstream_ssl, 1);

done:
	if (browser_ssl != NULL) {
		SSL_shutdown(browser_ssl);
		SSL_free(browser_ssl);
	}
	if (upstream_ssl != NULL) {
		SSL_shutdown(upstream_ssl);
		SSL_free(upstream_ssl);
	}
	SSL_CTX_free(server_ctx);
	SSL_CTX_free(client_ctx);
	close_fd(&server_fd);
}

static void *
connection_thread(void *arg)
{
	int client_fd = *(int *)arg;
	int id = new_conn_id();
	struct request req;

	free(arg);
	log_add(SIDE_C2S, "#%d cliente aceito", id);

	if (read_http_header(client_fd, &req) == -1 ||
	    parse_first_line(&req) == -1) {
		log_add(SIDE_C2S, "#%d header inicial invalido", id);
		close_fd(&client_fd);
		return NULL;
	}

	if (strcasecmp(req.method, "CONNECT") == 0)
		handle_https_mitm(id, client_fd, &req);
	else
		handle_plain_http(id, client_fd, &req);

	close_fd(&client_fd);
	log_add(SIDE_C2S, "#%d fechado", id);
	return NULL;
}

static void *
accept_thread(void *arg)
{
	int lfd = *(int *)arg;
	int client_fd, *owned_fd;
	pthread_t tid;

	while (running) {
		client_fd = accept(lfd, NULL, NULL);
		if (client_fd == -1) {
			if (errno == EINTR)
				continue;
			if (running)
				log_add(SIDE_C2S, "accept: %s", strerror(errno));
			continue;
		}

		owned_fd = malloc(sizeof(*owned_fd));
		if (owned_fd == NULL) {
			close(client_fd);
			continue;
		}
		*owned_fd = client_fd;
		if (pthread_create(&tid, NULL, connection_thread, owned_fd) != 0) {
			close(client_fd);
			free(owned_fd);
			continue;
		}
		pthread_detach(tid);
	}
	return NULL;
}

/* ------------------------------------------------------------------------- */
/* main                                                                       */
/* ------------------------------------------------------------------------- */

int
main(void)
{
	int lfd;
	pthread_t accept_tid;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	lfd = listen_socket();
	tui_init();

	if (load_or_create_ca() == -1) {
		endwin();
		fprintf(stderr, "nao consegui carregar/criar a CA local\n");
		return 1;
	}

	log_add(SIDE_C2S, "muninn ouvindo em %s:%s", LISTEN_HOST, LISTEN_PORT);
	log_add(SIDE_S2C, "aba de respostas pronta");
	log_add(SIDE_C2S, "importe %s como autoridade confiavel no navegador",
	    CA_CERT_FILE);

	if (pthread_create(&accept_tid, NULL, accept_thread, &lfd) != 0) {
		endwin();
		die("pthread_create");
	}

	while (running) {
		struct timespec ts;

		tui_input();
		tui_draw();
		ts.tv_sec = 0;
		ts.tv_nsec = 100000000L;
		nanosleep(&ts, NULL);
	}

	shutdown(lfd, SHUT_RDWR);
	close(lfd);
	pthread_join(accept_tid, NULL);
	endwin();

	X509_free(ca_cert);
	EVP_PKEY_free(ca_key);
	EVP_cleanup();
	return 0;
}
