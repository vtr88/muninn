#ifndef CAPTURE_H
#define CAPTURE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Limites padrao mantem o historico inteiramente em memoria. Testes podem
 * fornecer valores menores para exercitar truncamento e descarte.
 */
#define CAPTURE_DEFAULT_GLOBAL_BYTES (8U * 1024U * 1024U)
#define CAPTURE_DEFAULT_BODY_BYTES (64U * 1024U)
#define CAPTURE_DEFAULT_HEADER_BYTES (64U * 1024U)
#define CAPTURE_DEFAULT_TRANSACTIONS 2048U
#define CAPTURE_DEFAULT_CONNECTIONS 512U

enum capture_transaction_state {
	CAPTURE_REQUEST,
	CAPTURE_WAITING_RESPONSE,
	CAPTURE_RESPONSE,
	CAPTURE_COMPLETE,
	CAPTURE_INTERRUPTED,
	CAPTURE_ERROR
};

struct capture_limits {
	size_t global_bytes;
	size_t body_bytes;
	size_t header_bytes;
	size_t max_transactions;
	size_t max_connections;
};

struct capture_tls_view {
	char version[32];
	char cipher[96];
	char alpn[32];
	int present;
	int verified; /* 1 verificado, 0 falhou, -1 desativado, -2 nao se aplica */
};

struct capture_connection_view {
	int id;
	char client_host[128];
	char client_port[16];
	char target_host[256];
	char target_port[16];
	long long started_unix_ms;
	long long duration_ms;
	int active;
	int is_tls;
	int passthrough;
	struct capture_tls_view upstream_tls;
	struct capture_tls_view browser_tls;
};

struct capture_transaction_summary {
	uint64_t id;
	int connection_id;
	enum capture_transaction_state state;
	char method[32];
	char host[256];
	char target[1024];
	int status;
	long long started_unix_ms;
	long long duration_ms;
	uint64_t request_body_total;
	uint64_t response_body_total;
	size_t request_body_stored;
	size_t response_body_stored;
	int request_truncated;
	int response_truncated;
};

struct capture_message_view {
	char *start_line;
	char *headers;
	unsigned char *body;
	size_t body_len;
	uint64_t body_total;
	char content_type[128];
	char content_encoding[64];
	int headers_truncated;
	int body_truncated;
	int binary;
};

struct capture_transaction_view {
	struct capture_transaction_summary summary;
	struct capture_connection_view connection;
	struct capture_message_view request;
	struct capture_message_view response;
};

int capture_init(const struct capture_limits *);
void capture_cleanup(void);

int capture_connection_open(int, const char *, const char *);
void capture_connection_target(int, const char *, const char *, int, int);
void capture_connection_tls(int, int, const char *, const char *,
    const char *, int);
void capture_connection_close(int);

uint64_t capture_request_begin(int, const char *, const char *, const char *);
void capture_response_begin(uint64_t, const char *, int, const char *);
void capture_header(uint64_t, int, const char *);
void capture_headers_complete(uint64_t, int);
void capture_body(uint64_t, int, const unsigned char *, size_t);
void capture_request_complete(uint64_t);
void capture_response_complete(uint64_t, int);
void capture_transaction_error(uint64_t);

int capture_list_connections(struct capture_connection_view **, size_t *);
int capture_list_transactions(struct capture_transaction_summary **, size_t *);
int capture_list_transactions_matching(const char *,
    struct capture_transaction_summary **, size_t *);
size_t capture_clear(void);
int capture_get_transaction(uint64_t, struct capture_transaction_view *);
void capture_free_transaction(struct capture_transaction_view *);
size_t capture_memory_used(void);

#endif
