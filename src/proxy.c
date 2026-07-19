#include "muninn.h"

#include <sys/socket.h>

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/*
 * Os estados tornam explicito em qual operacao uma conexao se encontra. Na
 * proxima evolucao eles poderao alimentar a TUI; nesta etapa servem para que o
 * ciclo de vida nao fique espalhado em flags implicitas.
 */
enum connection_state {
	CONN_ACCEPTED,
	CONN_READING_HEADER,
	CONN_CONNECTING,
	CONN_TLS_UPSTREAM,
	CONN_TLS_BROWSER,
	CONN_RELAYING,
	CONN_CLOSING
};

struct connection {
	int id;
	int client_fd;
	enum connection_state state;
};

/* Copia os parametros negociados sem expor um SSL para fora desta thread. */
static void
capture_tls_session(int id, int upstream, SSL *ssl, int verified)
{
	const unsigned char *selected;
	const char *cipher, *version;
	unsigned int selected_len;
	char alpn[32];
	size_t copy_len;

	selected = NULL;
	selected_len = 0;
	SSL_get0_alpn_selected(ssl, &selected, &selected_len);
	copy_len = selected_len;
	if (copy_len >= sizeof(alpn))
		copy_len = sizeof(alpn) - 1;
	if (copy_len != 0)
		memcpy(alpn, selected, copy_len);
	alpn[copy_len] = '\0';
	version = SSL_get_version(ssl);
	cipher = SSL_get_cipher_name(ssl);
	capture_connection_tls(id, upstream, version, cipher, alpn, verified);
}

/*
 * As threads de conexao continuam detached, mas deixam de ser esquecidas.
 * main espera active_connections chegar a zero antes de liberar recursos
 * globais usados por elas.
 */
static pthread_mutex_t worker_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t worker_cond = PTHREAD_COND_INITIALIZER;
static unsigned int active_connections;

static void
worker_add(void)
{
	pthread_mutex_lock(&worker_lock);
	active_connections++;
	pthread_mutex_unlock(&worker_lock);
}

static void
worker_remove(void)
{
	pthread_mutex_lock(&worker_lock);
	if (active_connections > 0)
		active_connections--;
	if (active_connections == 0)
		pthread_cond_broadcast(&worker_cond);
	pthread_mutex_unlock(&worker_lock);
}

void
proxy_wait_connections(void)
{
	pthread_mutex_lock(&worker_lock);
	while (active_connections != 0)
		pthread_cond_wait(&worker_cond, &worker_lock);
	pthread_mutex_unlock(&worker_lock);
}

/* ------------------------------------------------------------------------- */
/* Fluxos HTTP e HTTPS                                                        */
/* ------------------------------------------------------------------------- */

static void
handle_plain_http(struct connection *conn, struct request *req)
{
	struct http_observer *observer;
	int server_fd;
	unsigned char out[HEADER_MAX + 1];
	size_t outlen;

	observer = NULL;
	server_fd = -1;
	if (parse_host_header(req) == -1 ||
	    make_origin_request(req, out, sizeof(out), &outlen) == -1) {
		log_add(SIDE_C2S, "#%d HTTP invalido", conn->id);
		return;
	}
	capture_connection_target(conn->id, req->host, req->port, 0, 0);

	log_add(SIDE_C2S, "#%d HTTP %s %s -> %s:%s", conn->id, req->method,
	    req->target, req->host, req->port);
	log_bytes(SIDE_C2S, conn->id, req->raw, req->raw_len);
	observer = http_observer_new(conn->id);
	http_observer_feed(observer, SIDE_C2S, req->raw, req->raw_len);

	conn->state = CONN_CONNECTING;
	server_fd = connect_host(req->host, req->port);
	if (server_fd == -1) {
		log_add(SIDE_C2S, "#%d falha conectando %s:%s", conn->id,
		    req->host, req->port);
		goto done;
	}

	if (socket_write_all(server_fd, out, outlen, CONNECT_TIMEOUT_MS) == -1)
		goto done;

	conn->state = CONN_RELAYING;
	if (relay_run(conn->id, conn->client_fd, server_fd, NULL, NULL,
	    observer) == -1 && running)
		log_add(SIDE_C2S, "#%d relay HTTP terminou com erro", conn->id);

done:
	http_observer_free(observer);
	close_fd(&server_fd);
}

static void
handle_https_mitm(struct connection *conn, struct request *req)
{
	struct http_observer *observer;
	SSL_CTX *server_ctx, *client_ctx;
	SSL *browser_ssl, *upstream_ssl;
	int server_fd;
	int passthrough;
	static const unsigned char ok[] =
	    "HTTP/1.1 200 Connection Established\r\n\r\n";

	observer = NULL;
	server_ctx = NULL;
	client_ctx = NULL;
	browser_ssl = NULL;
	upstream_ssl = NULL;
	server_fd = -1;

	if (parse_connect_target(req) == -1) {
		log_add(SIDE_C2S, "#%d CONNECT invalido: %s", conn->id,
		    req->target);
		return;
	}
	passthrough = config_host_passthrough(req->host);
	capture_connection_target(conn->id, req->host, req->port, 1,
	    passthrough);

	log_add(SIDE_C2S, "#%d CONNECT %s:%s", conn->id, req->host,
	    req->port);
	conn->state = CONN_CONNECTING;
	server_fd = connect_host(req->host, req->port);
	if (server_fd == -1) {
		log_add(SIDE_C2S, "#%d falha conectando upstream", conn->id);
		return;
	}

	/*
	 * Passthrough responde ao CONNECT, mas nao termina TLS. Navegador e
	 * servidor negociam diretamente; Muninn ve apenas bytes cifrados.
	 */
	if (passthrough) {
		if (socket_write_all(conn->client_fd, ok, sizeof(ok) - 1,
		    CONNECT_TIMEOUT_MS) == -1)
			goto done;
		log_add(SIDE_S2C, "#%d 200 Connection Established", conn->id);
		log_add(SIDE_C2S, "#%d passthrough TLS opaco para %s", conn->id,
		    req->host);
		conn->state = CONN_RELAYING;
		if (relay_run(conn->id, conn->client_fd, server_fd, NULL, NULL,
		    NULL) == -1 && running)
			log_add(SIDE_C2S, "#%d passthrough terminou com erro",
			    conn->id);
		goto done;
	}

	conn->state = CONN_TLS_UPSTREAM;
	client_ctx = make_client_ctx();
	upstream_ssl = client_ctx == NULL ? NULL : SSL_new(client_ctx);
	if (upstream_ssl == NULL) {
		tls_log_errors(SIDE_C2S, conn->id,
		    "criacao do cliente TLS falhou");
		goto done;
	}
	SSL_set_fd(upstream_ssl, server_fd);
	if (tls_configure_upstream(upstream_ssl, req->host) == -1) {
		tls_log_errors(SIDE_C2S, conn->id,
		    "configuracao TLS upstream falhou");
		goto done;
	}
	if (tls_handshake(upstream_ssl, 0, TLS_TIMEOUT_MS) == -1) {
		if (running) {
			tls_log_errors(SIDE_C2S, conn->id, "TLS upstream falhou");
			log_add(SIDE_C2S,
			    "#%d use --insecure-upstream somente se for intencional",
			    conn->id);
		}
		goto done;
	}
	tls_log_session(SIDE_C2S, conn->id, "TLS upstream", upstream_ssl, 1);
	capture_tls_session(conn->id, 1, upstream_ssl,
	    config_insecure_upstream() ? -1 : 1);

	if (socket_write_all(conn->client_fd, ok, sizeof(ok) - 1,
	    CONNECT_TIMEOUT_MS) == -1)
		goto done;
	log_add(SIDE_S2C, "#%d 200 Connection Established", conn->id);

	conn->state = CONN_TLS_BROWSER;
	server_ctx = make_server_ctx_for_host(req->host);
	browser_ssl = server_ctx == NULL ? NULL : SSL_new(server_ctx);
	if (browser_ssl == NULL) {
		tls_log_errors(SIDE_C2S, conn->id,
		    "certificado MITM ou contexto TLS falhou");
		goto done;
	}
	SSL_set_fd(browser_ssl, conn->client_fd);
	if (tls_handshake(browser_ssl, 1, TLS_TIMEOUT_MS) == -1) {
		if (running) {
			tls_log_errors(SIDE_C2S, conn->id, "TLS navegador falhou");
			log_add(SIDE_C2S,
			    "#%d pinning? tente --passthrough %s", conn->id,
			    req->host);
		}
		goto done;
	}

	tls_log_session(SIDE_C2S, conn->id, "TLS navegador", browser_ssl, 0);
	capture_tls_session(conn->id, 0, browser_ssl, -2);
	log_add(SIDE_C2S, "#%d MITM ativo para %s", conn->id, req->host);
	observer = http_observer_new(conn->id);
	conn->state = CONN_RELAYING;
	if (relay_run(conn->id, conn->client_fd, server_fd, browser_ssl,
	    upstream_ssl, observer) == -1 && running)
		log_add(SIDE_C2S, "#%d relay HTTPS terminou com erro", conn->id);

done:
	/*
	 * Cada SSL pertence exclusivamente a esta thread. Assim shutdown/free
	 * jamais concorrem com uma leitura ou escrita ainda em andamento.
	 */
	http_observer_free(observer);
	if (browser_ssl != NULL) {
		(void)SSL_shutdown(browser_ssl);
		SSL_free(browser_ssl);
	}
	if (upstream_ssl != NULL) {
		(void)SSL_shutdown(upstream_ssl);
		SSL_free(upstream_ssl);
	}
	SSL_CTX_free(server_ctx);
	SSL_CTX_free(client_ctx);
	close_fd(&server_fd);
}

static void *
connection_thread(void *arg)
{
	struct connection *conn;
	struct request req;

	conn = arg;
	log_add(SIDE_C2S, "#%d cliente aceito", conn->id);
	conn->state = CONN_READING_HEADER;

	if (read_http_header(conn->client_fd, &req) == -1 ||
	    parse_first_line(&req) == -1) {
		if (running)
			log_add(SIDE_C2S, "#%d header inicial invalido", conn->id);
		goto done;
	}

	if (strcasecmp(req.method, "CONNECT") == 0)
		handle_https_mitm(conn, &req);
	else
		handle_plain_http(conn, &req);

done:
	conn->state = CONN_CLOSING;
	close_fd(&conn->client_fd);
	capture_connection_close(conn->id);
	log_add(SIDE_C2S, "#%d fechado", conn->id);
	worker_remove();
	free(conn);
	return NULL;
}

void *
accept_thread(void *arg)
{
	struct connection *conn;
	struct sockaddr_storage peer;
	socklen_t peer_len;
	char client_host[128], client_port[16];
	int client_fd, lfd;
	pthread_t tid;

	lfd = *(int *)arg;
	while (running) {
		peer_len = sizeof(peer);
		client_fd = accept(lfd, (struct sockaddr *)&peer, &peer_len);
		if (client_fd == -1) {
			if (errno == EINTR)
				continue;
			if (running)
				log_add(SIDE_C2S, "accept: %s", strerror(errno));
			continue;
		}
		if (set_nonblocking(client_fd) == -1) {
			close(client_fd);
			continue;
		}

		conn = calloc(1, sizeof(*conn));
		if (conn == NULL) {
			close(client_fd);
			continue;
		}
		conn->id = new_conn_id();
		conn->client_fd = client_fd;
		conn->state = CONN_ACCEPTED;
		client_host[0] = '\0';
		client_port[0] = '\0';
		if (getnameinfo((struct sockaddr *)&peer, peer_len, client_host,
		    sizeof(client_host), client_port, sizeof(client_port),
		    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
			(void)snprintf(client_host, sizeof(client_host), "desconhecido");
			client_port[0] = '\0';
		}
		(void)capture_connection_open(conn->id, client_host, client_port);

		/*
		 * O contador sobe antes de pthread_create para que main nunca veja
		 * zero entre a criacao logica e o inicio real da thread.
		 */
		worker_add();
		if (pthread_create(&tid, NULL, connection_thread, conn) != 0) {
			worker_remove();
			capture_connection_close(conn->id);
			close(client_fd);
			free(conn);
			continue;
		}
		pthread_detach(tid);
	}
	return NULL;
}
