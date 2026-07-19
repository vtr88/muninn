#include "muninn.h"

#include <poll.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t id_lock = PTHREAD_MUTEX_INITIALIZER;
static int next_id = 1;
volatile sig_atomic_t running = 1;

/* ------------------------------------------------------------------------- */
/* Utilitarios pequenos                                                       */
/* ------------------------------------------------------------------------- */

void
die(const char *msg)
{
	perror(msg);
	exit(1);
}

void
on_signal(int signo)
{
	(void)signo;
	running = 0;
}

int
new_conn_id(void)
{
	int id;

	pthread_mutex_lock(&id_lock);
	id = next_id++;
	pthread_mutex_unlock(&id_lock);
	return id;
}

void
close_fd(int *fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

/*
 * CLOCK_MONOTONIC mede passagem de tempo sem depender do relogio civil.
 * Se o usuario corrigir a hora do sistema durante um acesso, nossos timeouts
 * continuam corretos porque este relogio nunca volta para tras.
 */
long long
monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		return 0;
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/*
 * Espera um descritor ficar pronto, mas acorda pelo menos uma vez por segundo.
 * Esse despertar periodico permite que todas as conexoes percebam running=0
 * rapidamente quando o usuario aperta q.
 *
 * Retorno:
 *   > 0: mascara revents produzida por poll(2)
 *     0: deadline expirou ou o programa esta encerrando
 *    -1: poll falhou
 */
int
wait_fd_until(int fd, short events, long long deadline)
{
	struct pollfd pfd;
	long long left;
	int timeout, n;

	pfd.fd = fd;
	pfd.events = events;
	for (;;) {
		if (!running)
			return 0;
		left = deadline - monotonic_ms();
		if (left <= 0)
			return 0;
		timeout = left > POLL_TICK_MS ? POLL_TICK_MS : (int)left;
		pfd.revents = 0;
		n = poll(&pfd, 1, timeout);
		if (n > 0)
			return pfd.revents;
		if (n == 0)
			continue;
		if (errno != EINTR)
			return -1;
	}
}
