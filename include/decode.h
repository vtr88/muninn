#ifndef DECODE_H
#define DECODE_H

#include <stddef.h>

#include "capture.h"

/* Limite separado do capture evita expansao ilimitada de dados comprimidos. */
#define BODY_DECODE_MAX_BYTES (256U * 1024U)

enum body_decode_status {
	BODY_DECODE_RAW,
	BODY_DECODE_COMPLETE,
	BODY_DECODE_PARTIAL,
	BODY_DECODE_LIMIT,
	BODY_DECODE_UNSUPPORTED,
	BODY_DECODE_ERROR
};

struct body_decode_view {
	unsigned char *data;
	size_t length;
	enum body_decode_status status;
	int binary;
};

int body_decode(const struct capture_message_view *, size_t,
    struct body_decode_view *);
void body_decode_free(struct body_decode_view *);
const char *body_decode_status_name(enum body_decode_status);

#endif
