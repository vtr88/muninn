#include "muninn.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Configura opcoes pequenas que pertencem ao descritor, nao ao protocolo.
 * Estas funcoes ficam privadas porque nenhum outro modulo precisa saber como
 * fcntl ou SO_REUSEADDR sao aplicados.
 */
static int
set_reuseaddr(int fd)
{
	int yes = 1;

	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

int
set_nonblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		return -1;
	if ((flags & O_NONBLOCK) != 0)
		return 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ------------------------------------------------------------------------- */
/* Sockets                                                                    */
/* ------------------------------------------------------------------------- */

int
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

/*
 * connect(2) em socket nao bloqueante normalmente retorna EINPROGRESS. Quando
 * poll informa escrita, SO_ERROR contem o resultado real da tentativa.
 * Todas as alternativas retornadas por getaddrinfo compartilham o mesmo
 * deadline, evitando que muitos enderecos multipliquem o timeout.
 */
int
connect_host(const char *host, const char *port)
{
	struct addrinfo hints, *res, *ai;
	long long deadline;
	socklen_t error_len;
	int fd = -1, error, ready;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error = getaddrinfo(host, port, &hints, &res);
	if (error != 0)
		return -1;
	deadline = monotonic_ms() + CONNECT_TIMEOUT_MS;

	for (ai = res; ai != NULL && running; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd == -1)
			continue;
		if (set_nonblocking(fd) == -1)
			goto next;

		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		if (errno != EINPROGRESS)
			goto next;

		ready = wait_fd_until(fd, POLLOUT, deadline);
		if (ready <= 0 || (ready & POLLNVAL))
			goto next;

		error = 0;
		error_len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 &&
		    error == 0)
			break;

next:
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

/*
 * Envia um bloco inteiro sem supor que send(2) escrevera tudo de uma vez.
 * E usado antes do relay para a requisicao HTTP inicial e para a resposta 200
 * do CONNECT. O relay possui buffers proprios para o restante do fluxo.
 */
int
socket_write_all(int fd, const unsigned char *buf, size_t len, int timeout_ms)
{
	long long deadline;
	size_t off;
	int ready;
	ssize_t n;

	deadline = monotonic_ms() + timeout_ms;
	off = 0;
	while (off < len && running) {
		n = send(fd, buf + off, len - off, 0);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n == -1 && errno == EINTR)
			continue;
		if (n != -1 || (errno != EAGAIN && errno != EWOULDBLOCK))
			return -1;
		ready = wait_fd_until(fd, POLLOUT, deadline);
		if (ready <= 0 || (ready & (POLLERR | POLLNVAL)))
			return -1;
	}
	return off == len ? 0 : -1;
}
