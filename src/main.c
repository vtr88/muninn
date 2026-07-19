#include "muninn.h"

#include <sys/socket.h>

#include <curses.h>
#include <openssl/err.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* main                                                                       */
/* ------------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
	enum app_mode mode;
	int lfd;
	pthread_t accept_tid;

	if (config_parse(argc, argv, &mode) == -1) {
		config_usage();
		return 1;
	}
	if (mode == APP_HELP) {
		config_usage();
		return 0;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	/* Comandos de CA nao precisam abrir porta nem inicializar ncurses. */
	if (mode != APP_RUN) {
		int status;

		if (mode == APP_CA_CREATE)
			status = tls_ca_create_command();
		else if (mode == APP_CA_SHOW)
			status = tls_ca_show_command();
		else
			status = tls_ca_fingerprint_command();
		tls_cleanup();
		return status == 0 ? 0 : 1;
	}

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
	if (config_insecure_upstream())
		log_add(SIDE_C2S,
		    "ATENCAO: verificacao TLS upstream esta desativada");

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

	/*
	 * As conexoes sao destacadas, mas possuem um contador protegido. Esperamos
	 * todas sairem dos loops de poll antes de destruir ncurses e a CA global.
	 */
	proxy_wait_connections();
	endwin();

	tls_cleanup();
	EVP_cleanup();
	return 0;
}
