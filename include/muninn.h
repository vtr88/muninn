#ifndef MUNINN_H
#define MUNINN_H

#include <signal.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "capture.h"

#ifndef MUNINN_VERSION
#define MUNINN_VERSION "0.1.0"
#endif

/*
 * Este cabecalho descreve somente os contratos compartilhados pelos modulos.
 * Detalhes internos continuam privados em cada arquivo .c.
 */

#define LISTEN_HOST "127.0.0.1"
#define LISTEN_PORT "13337"
#define BACKLOG 128

#define HEADER_MAX 65536
#define RELAY_BUF 8192

#define CONNECT_TIMEOUT_MS 10000
#define HEADER_TIMEOUT_MS 10000
#define TLS_TIMEOUT_MS 10000
#define RELAY_IDLE_TIMEOUT_MS 120000
#define POLL_TICK_MS 1000

#define LOG_LINES 1024
#define LOG_LINE 240

#define CA_KEY_FILE "muninn-ca-key.pem"
#define CA_CERT_FILE "muninn-ca-cert.pem"

enum side {
	SIDE_C2S = 0, /* client -> server: navegador indo para fora */
	SIDE_S2C = 1  /* server -> client: servidor voltando ao navegador */
};

enum app_mode {
	APP_RUN,
	APP_CA_CREATE,
	APP_CA_SHOW,
	APP_CA_FINGERPRINT,
	APP_VERSION,
	APP_HELP
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

/*
 * O observador HTTP e opaco para o relay. Apenas os testes e, futuramente,
 * a TUI consultam estes contadores agregados.
 */
struct http_observer;

struct http_observer_stats {
	unsigned int requests;
	unsigned int responses;
	unsigned int parse_errors;
	unsigned long long request_body_bytes;
	unsigned long long response_body_bytes;
	int tunneled;
};

extern volatile sig_atomic_t running;

/* config.c */
int config_parse(int, char **, enum app_mode *);
int config_insecure_upstream(void);
int config_host_passthrough(const char *);
const struct capture_limits *config_capture_limits(void);
void config_usage(void);

/* util.c */
void die(const char *);
void on_signal(int);
int new_conn_id(void);
void close_fd(int *);
long long monotonic_ms(void);
int wait_fd_until(int, short, long long);

/* tui.c */
void log_add(enum side, const char *, ...);
void log_bytes(enum side, int, const unsigned char *, size_t);
void tui_init(void);
void tui_cleanup(void);
void tui_input(void);
void tui_draw(void);

/* net.c */
int listen_socket(void);
int connect_host(const char *, const char *);
int set_nonblocking(int);
int socket_write_all(int, const unsigned char *, size_t, int);

/* http.c */
int read_http_header(int, struct request *);
int parse_first_line(struct request *);
int parse_host_header(struct request *);
int parse_connect_target(struct request *);
int make_origin_request(struct request *, unsigned char *, size_t, size_t *);
struct http_observer *http_observer_new(int);
void http_observer_feed(struct http_observer *, enum side,
    const unsigned char *, size_t);
void http_observer_eof(struct http_observer *, enum side);
void http_observer_get_stats(const struct http_observer *,
    struct http_observer_stats *);
void http_observer_free(struct http_observer *);

/* tls.c */
int load_or_create_ca(void);
int tls_ca_create_command(void);
int tls_ca_show_command(void);
int tls_ca_fingerprint_command(void);
SSL_CTX *make_server_ctx_for_host(const char *);
SSL_CTX *make_client_ctx(void);
int tls_configure_upstream(SSL *, const char *);
int tls_handshake(SSL *, int, int);
void tls_log_errors(enum side, int, const char *);
void tls_log_session(enum side, int, const char *, SSL *, int);
void tls_cleanup(void);

/* relay.c */
int relay_run(int, int, int, SSL *, SSL *, struct http_observer *);

/* proxy.c */
void *accept_thread(void *);
void proxy_wait_connections(void);

#endif
