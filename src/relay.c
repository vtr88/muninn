#include "muninn.h"

#include <sys/socket.h>

#include <errno.h>
#include <poll.h>
#include <string.h>

/*
 * Um endpoint representa uma ponta da conexao. Se ssl for NULL, as operacoes
 * usam recv/send diretamente. Caso contrario, usam SSL_read/SSL_write.
 */
struct endpoint {
	int fd;
	SSL *ssl;
};

/*
 * Cada flow possui um unico buffer pendente. Enquanto ele contem bytes,
 * paramos de ler a origem e tentamos esvazia-lo no destino. Isso cria
 * backpressure natural: um servidor lento nao permite que o proxy consuma
 * memoria sem limite.
 */
struct flow {
	struct endpoint *src;
	struct endpoint *dst;
	enum side side;
	unsigned char buf[RELAY_BUF];
	size_t len;
	size_t off;
	short read_wait;
	short write_wait;
	int done;
};

enum io_status {
	IO_WAIT,
	IO_PROGRESS,
	IO_EOF,
	IO_ERROR
};

/* Acrescenta um interesse sem apagar eventos pedidos pelo fluxo oposto. */
static void
add_event(struct pollfd *pfd, int index, short event)
{
	pfd[index].events |= event;
}

static int
endpoint_index(struct endpoint *endpoint, struct endpoint *client)
{
	return endpoint == client ? 0 : 1;
}

/*
 * Converte os resultados especiais do OpenSSL para eventos poll. Como toda
 * chamada acontece nesta unica thread, nunca existem SSL_read e SSL_write
 * concorrentes sobre o mesmo SSL.
 */
static enum io_status
endpoint_read(struct endpoint *endpoint, unsigned char *buf, size_t len,
    size_t *received, short *wait_event)
{
	int error, n;
	ssize_t plain_n;

	if (endpoint->ssl == NULL) {
		plain_n = recv(endpoint->fd, buf, len, 0);
		if (plain_n > 0) {
			*received = (size_t)plain_n;
			return IO_PROGRESS;
		}
		if (plain_n == 0)
			return IO_EOF;
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
			*wait_event = POLLIN;
			return IO_WAIT;
		}
		return IO_ERROR;
	}

	n = SSL_read(endpoint->ssl, buf, (int)len);
	if (n > 0) {
		*received = (size_t)n;
		return IO_PROGRESS;
	}
	error = SSL_get_error(endpoint->ssl, n);
	if (error == SSL_ERROR_WANT_READ) {
		*wait_event = POLLIN;
		return IO_WAIT;
	}
	if (error == SSL_ERROR_WANT_WRITE) {
		*wait_event = POLLOUT;
		return IO_WAIT;
	}
	if (error == SSL_ERROR_ZERO_RETURN)
		return IO_EOF;
	if (error == SSL_ERROR_SYSCALL && n == 0)
		return IO_EOF;
	return IO_ERROR;
}

static enum io_status
endpoint_write(struct endpoint *endpoint, const unsigned char *buf, size_t len,
    size_t *written, short *wait_event)
{
	int error, n;
	ssize_t plain_n;

	if (endpoint->ssl == NULL) {
		plain_n = send(endpoint->fd, buf, len, 0);
		if (plain_n > 0) {
			*written = (size_t)plain_n;
			return IO_PROGRESS;
		}
		if (plain_n == -1 &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
			*wait_event = POLLOUT;
			return IO_WAIT;
		}
		return IO_ERROR;
	}

	n = SSL_write(endpoint->ssl, buf, (int)len);
	if (n > 0) {
		*written = (size_t)n;
		return IO_PROGRESS;
	}
	error = SSL_get_error(endpoint->ssl, n);
	if (error == SSL_ERROR_WANT_READ) {
		*wait_event = POLLIN;
		return IO_WAIT;
	}
	if (error == SSL_ERROR_WANT_WRITE) {
		*wait_event = POLLOUT;
		return IO_WAIT;
	}
	if (error == SSL_ERROR_ZERO_RETURN)
		return IO_EOF;
	return IO_ERROR;
}

/*
 * Propaga o fim de uma direcao. TCP possui half-close real. Em TLS, a primeira
 * chamada de SSL_shutdown envia close_notify; nao esperamos a resposta aqui,
 * pois ela chegara pela direcao oposta do mesmo loop.
 */
static void
endpoint_finish_write(struct endpoint *endpoint)
{
	if (endpoint->ssl != NULL)
		(void)SSL_shutdown(endpoint->ssl);
	else
		(void)shutdown(endpoint->fd, SHUT_WR);
}

static int
flow_has_pending(const struct flow *flow)
{
	return flow->off < flow->len;
}

static enum io_status
flow_read(struct flow *flow, int id, struct http_observer *observer)
{
	enum io_status status;
	size_t received;

	received = 0;
	status = endpoint_read(flow->src, flow->buf, sizeof(flow->buf),
	    &received, &flow->read_wait);
	if (status == IO_PROGRESS) {
		flow->off = 0;
		flow->len = received;
		flow->read_wait = POLLIN;
		http_observer_feed(observer, flow->side, flow->buf, received);
		log_bytes(flow->side, id, flow->buf, received);
	} else if (status == IO_EOF) {
		flow->done = 1;
		http_observer_eof(observer, flow->side);
		endpoint_finish_write(flow->dst);
	}
	return status;
}

static enum io_status
flow_write(struct flow *flow)
{
	enum io_status status;
	size_t written;

	written = 0;
	status = endpoint_write(flow->dst, flow->buf + flow->off,
	    flow->len - flow->off, &written, &flow->write_wait);
	if (status == IO_PROGRESS) {
		flow->off += written;
		flow->write_wait = POLLOUT;
		if (flow->off == flow->len) {
			flow->off = 0;
			flow->len = 0;
		}
	}
	return status;
}

/*
 * Encaminha as duas direcoes em uma unica thread.
 *
 * client[0] e server[1] compartilham o mesmo poll. Cada fluxo adiciona apenas
 * o evento de que precisa naquele momento. Isso evita busy-loop em POLLOUT e
 * tambem respeita pedidos incomuns do OpenSSL, como SSL_read precisar primeiro
 * que o socket fique gravavel.
 */
int
relay_run(int id, int client_fd, int server_fd, SSL *client_ssl,
    SSL *server_ssl, struct http_observer *observer)
{
	struct endpoint client, server;
	struct flow flows[2];
	struct pollfd pfd[2];
	enum io_status status;
	long long idle_deadline, left;
	int dst_index, immediate, n, src_index, timeout;
	int i;

	client.fd = client_fd;
	client.ssl = client_ssl;
	server.fd = server_fd;
	server.ssl = server_ssl;

	memset(flows, 0, sizeof(flows));
	flows[0].src = &client;
	flows[0].dst = &server;
	flows[0].side = SIDE_C2S;
	flows[1].src = &server;
	flows[1].dst = &client;
	flows[1].side = SIDE_S2C;
	for (i = 0; i < 2; i++) {
		flows[i].read_wait = POLLIN;
		flows[i].write_wait = POLLOUT;
	}

	idle_deadline = monotonic_ms() + RELAY_IDLE_TIMEOUT_MS;
	while (running && (!flows[0].done || !flows[1].done)) {
		memset(pfd, 0, sizeof(pfd));
		pfd[0].fd = client_fd;
		pfd[1].fd = server_fd;
		immediate = 0;

		for (i = 0; i < 2; i++) {
			if (flows[i].done)
				continue;
			src_index = endpoint_index(flows[i].src, &client);
			dst_index = endpoint_index(flows[i].dst, &client);
			if (flow_has_pending(&flows[i])) {
				add_event(pfd, dst_index, flows[i].write_wait);
			} else {
				add_event(pfd, src_index, flows[i].read_wait);
				if (flows[i].src->ssl != NULL &&
				    SSL_pending(flows[i].src->ssl) > 0)
					immediate = 1;
			}
		}

		left = idle_deadline - monotonic_ms();
		if (left <= 0) {
			log_add(SIDE_C2S, "#%d relay expirou por inatividade", id);
			return 0;
		}
		timeout = left > POLL_TICK_MS ? POLL_TICK_MS : (int)left;
		if (immediate)
			timeout = 0;

		n = poll(pfd, 2, timeout);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (pfd[0].revents & POLLNVAL || pfd[1].revents & POLLNVAL)
			return -1;

		/*
		 * Primeiro esvaziamos buffers. So depois lemos mais bytes. Essa
		 * ordem preserva o limite fixo de memoria e reduz latencia.
		 */
		for (i = 0; i < 2; i++) {
			if (flows[i].done || !flow_has_pending(&flows[i]))
				continue;
			dst_index = endpoint_index(flows[i].dst, &client);
			if ((pfd[dst_index].revents &
			    (flows[i].write_wait | POLLHUP | POLLERR)) == 0)
				continue;
			status = flow_write(&flows[i]);
			if (status == IO_ERROR || status == IO_EOF)
				return -1;
			if (status == IO_PROGRESS)
				idle_deadline = monotonic_ms() + RELAY_IDLE_TIMEOUT_MS;
		}

		for (i = 0; i < 2; i++) {
			if (flows[i].done || flow_has_pending(&flows[i]))
				continue;
			src_index = endpoint_index(flows[i].src, &client);
			if ((pfd[src_index].revents & flows[i].read_wait) == 0 &&
			    !(flows[i].src->ssl != NULL &&
			    SSL_pending(flows[i].src->ssl) > 0) &&
			    (pfd[src_index].revents & (POLLHUP | POLLERR)) == 0)
				continue;
			status = flow_read(&flows[i], id, observer);
			if (status == IO_ERROR)
				return -1;
			if (status == IO_PROGRESS)
				idle_deadline = monotonic_ms() + RELAY_IDLE_TIMEOUT_MS;
		}
	}
	return running ? 0 : -1;
}
