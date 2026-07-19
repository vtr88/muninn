#include "decode.h"

#include <brotli/decode.h>
#include <zlib.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define ENCODING_MAX 4
#define ENCODING_NAME_MAX 24

static int
byte_is_binary(unsigned char byte)
{
	return byte == 0 || (byte < 0x20 && byte != '\t' && byte != '\n' &&
	    byte != '\r') || byte == 0x7f;
}

static int
detect_binary(const unsigned char *data, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++) {
		if (byte_is_binary(data[i]))
			return 1;
	}
	return 0;
}

/*
 * inflate recebe uInt, mas os limites sao size_t. Alimentamos entrada e saida
 * em blocos para que a rotina continue correta mesmo com limites grandes.
 */
static enum body_decode_status
decode_zlib_once(const unsigned char *input, size_t input_length,
	unsigned char *output, size_t output_limit, size_t *output_length,
	int window_bits)
{
	z_stream stream;
	size_t input_offset, output_offset;
	int result;

	memset(&stream, 0, sizeof(stream));
	if (inflateInit2(&stream, window_bits) != Z_OK)
		return BODY_DECODE_ERROR;
	input_offset = 0;
	output_offset = 0;
	result = Z_OK;
	while (result == Z_OK) {
		if (stream.avail_in == 0 && input_offset < input_length) {
			stream.next_in = (Bytef *)input + input_offset;
			stream.avail_in = input_length - input_offset > UINT_MAX ?
			    UINT_MAX : (uInt)(input_length - input_offset);
			input_offset += stream.avail_in;
		}
		if (stream.avail_out == 0 && output_offset < output_limit) {
			stream.next_out = output + output_offset;
			stream.avail_out = output_limit - output_offset > UINT_MAX ?
			    UINT_MAX : (uInt)(output_limit - output_offset);
			output_offset += stream.avail_out;
		}
		result = inflate(&stream, Z_NO_FLUSH);
		if (stream.avail_out == 0 && output_offset == output_limit &&
		    result != Z_STREAM_END) {
			*output_length = output_limit;
			inflateEnd(&stream);
			return BODY_DECODE_LIMIT;
		}
		if (stream.avail_in == 0 && input_offset == input_length &&
		    result == Z_OK)
			break;
	}
	*output_length = (size_t)stream.total_out;
	inflateEnd(&stream);
	if (result == Z_STREAM_END)
		return BODY_DECODE_COMPLETE;
	if ((result == Z_OK || result == Z_BUF_ERROR) && *output_length != 0)
		return BODY_DECODE_PARTIAL;
	return BODY_DECODE_ERROR;
}

static enum body_decode_status
decode_zlib(const char *encoding, const unsigned char *input,
	size_t input_length, unsigned char *output, size_t output_limit,
	size_t *output_length)
{
	enum body_decode_status status;

	if (strcasecmp(encoding, "gzip") == 0 ||
	    strcasecmp(encoding, "x-gzip") == 0)
		return decode_zlib_once(input, input_length, output, output_limit,
		    output_length, 16 + MAX_WBITS);

	status = decode_zlib_once(input, input_length, output, output_limit,
	    output_length, MAX_WBITS);
	if (status == BODY_DECODE_ERROR) {
		/* Alguns servidores antigos enviam deflate cru, sem cabecalho zlib. */
		status = decode_zlib_once(input, input_length, output, output_limit,
		    output_length, -MAX_WBITS);
	}
	return status;
}

static enum body_decode_status
decode_brotli(const unsigned char *input, size_t input_length,
	unsigned char *output, size_t output_limit, size_t *output_length)
{
	BrotliDecoderState *state;
	BrotliDecoderResult result;
	size_t available_in, available_out;
	const uint8_t *next_in;
	uint8_t *next_out;

	available_in = input_length;
	next_in = input;
	available_out = output_limit;
	next_out = output;
	state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
	if (state == NULL)
		return BODY_DECODE_ERROR;
	result = BrotliDecoderDecompressStream(state, &available_in, &next_in,
	    &available_out, &next_out, NULL);
	BrotliDecoderDestroyInstance(state);
	*output_length = output_limit - available_out;
	if (result == BROTLI_DECODER_RESULT_SUCCESS)
		return BODY_DECODE_COMPLETE;
	if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT)
		return BODY_DECODE_LIMIT;
	if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT &&
	    *output_length != 0)
		return BODY_DECODE_PARTIAL;
	return BODY_DECODE_ERROR;
}

static int
parse_encodings(const char *header,
	char encodings[ENCODING_MAX][ENCODING_NAME_MAX], size_t *count)
{
	char copy[128], *cursor, *end, *save, *token;
	size_t length;

	*count = 0;
	if (header == NULL || *header == '\0')
		return 0;
	(void)snprintf(copy, sizeof(copy), "%s", header);
	save = NULL;
	for (token = strtok_r(copy, ",", &save); token != NULL;
	    token = strtok_r(NULL, ",", &save)) {
		cursor = token;
		while (*cursor != '\0' && isspace((unsigned char)*cursor))
			cursor++;
		end = cursor + strlen(cursor);
		while (end > cursor && isspace((unsigned char)end[-1]))
			*--end = '\0';
		if (*cursor == '\0' || *count == ENCODING_MAX)
			return -1;
		length = strlen(cursor);
		if (length >= ENCODING_NAME_MAX)
			return -1;
		(void)snprintf(encodings[*count], ENCODING_NAME_MAX, "%s", cursor);
		(*count)++;
	}
	return 0;
}

int
body_decode(const struct capture_message_view *message, size_t output_limit,
	struct body_decode_view *view)
{
	char encodings[ENCODING_MAX][ENCODING_NAME_MAX];
	unsigned char *current, *decoded;
	size_t count, current_length, decoded_length, i;
	enum body_decode_status status, worst;

	if (message == NULL || view == NULL || output_limit == 0)
		return -1;
	memset(view, 0, sizeof(*view));
	view->status = BODY_DECODE_RAW;
	if (message->body_len == 0 || message->content_encoding[0] == '\0' ||
	    strcasecmp(message->content_encoding, "identity") == 0)
		return 0;
	if (parse_encodings(message->content_encoding, encodings, &count) == -1)
		return 0;
	for (i = 0; i < count; i++) {
		if (strcasecmp(encodings[i], "gzip") != 0 &&
		    strcasecmp(encodings[i], "x-gzip") != 0 &&
		    strcasecmp(encodings[i], "deflate") != 0 &&
		    strcasecmp(encodings[i], "br") != 0) {
			view->status = BODY_DECODE_UNSUPPORTED;
			return 0;
		}
	}
	current = malloc(message->body_len);
	if (current == NULL)
		return -1;
	memcpy(current, message->body, message->body_len);
	current_length = message->body_len;
	worst = BODY_DECODE_COMPLETE;
	for (i = count; i > 0; i--) {
		decoded = malloc(output_limit);
		if (decoded == NULL) {
			free(current);
			return -1;
		}
		decoded_length = 0;
		if (strcasecmp(encodings[i - 1], "br") == 0) {
			status = decode_brotli(current, current_length, decoded,
			    output_limit, &decoded_length);
		} else {
			status = decode_zlib(encodings[i - 1], current,
			    current_length, decoded, output_limit, &decoded_length);
		}
		free(current);
		if (status == BODY_DECODE_ERROR) {
			free(decoded);
			view->status = BODY_DECODE_ERROR;
			return 0;
		}
		if (status > worst)
			worst = status;
		current = decoded;
		current_length = decoded_length;
	}
	view->data = current;
	view->length = current_length;
	view->status = message->body_truncated && worst == BODY_DECODE_COMPLETE ?
	    BODY_DECODE_PARTIAL : worst;
	view->binary = detect_binary(view->data, view->length);
	return 0;
}

void
body_decode_free(struct body_decode_view *view)
{
	if (view == NULL)
		return;
	free(view->data);
	memset(view, 0, sizeof(*view));
}

const char *
body_decode_status_name(enum body_decode_status status)
{
	switch (status) {
	case BODY_DECODE_RAW:
		return "original";
	case BODY_DECODE_COMPLETE:
		return "decodificado";
	case BODY_DECODE_PARTIAL:
		return "decodificacao parcial";
	case BODY_DECODE_LIMIT:
		return "decodificacao truncada";
	case BODY_DECODE_UNSUPPORTED:
		return "encoding nao suportado";
	case BODY_DECODE_ERROR:
		return "falha ao decodificar";
	}
	return "estado desconhecido";
}
