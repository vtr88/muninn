#include "muninn.h"

#include <sys/socket.h>

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

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

int
read_http_header(int fd, struct request *req)
{
	long long deadline;
	int ready;
	ssize_t n;

	memset(req, 0, sizeof(*req));
	deadline = monotonic_ms() + HEADER_TIMEOUT_MS;
	while (req->raw_len < sizeof(req->raw)) {
		n = recv(fd, req->raw + req->raw_len,
		    sizeof(req->raw) - req->raw_len, 0);
		if (n > 0) {
			req->raw_len += (size_t)n;
			if (header_end(req->raw, req->raw_len) != NULL)
				return 0;
			continue;
		}
		if (n == 0)
			return -1;
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			return -1;
		if (errno == EINTR)
			continue;

		/*
		 * O socket do navegador e nao bloqueante. Em vez de girar a CPU
		 * enquanto o header chega em partes, dormimos ate haver leitura.
		 */
		ready = wait_fd_until(fd, POLLIN, deadline);
		if (ready <= 0 || (ready & (POLLERR | POLLNVAL)))
			return -1;
	}
	return -1;
}

int
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

int
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

int
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
int
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
