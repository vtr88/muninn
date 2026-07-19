#include "decode.h"

#include <brotli/encode.h>
#include <zlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: falhou: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

static int
make_gzip(const unsigned char *input, size_t input_length,
	unsigned char **output, size_t *output_length)
{
	z_stream stream;
	size_t capacity;
	int result;

	memset(&stream, 0, sizeof(stream));
	if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
	    16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		return -1;
	capacity = deflateBound(&stream, input_length);
	*output = malloc(capacity);
	if (*output == NULL) {
		deflateEnd(&stream);
		return -1;
	}
	stream.next_in = (Bytef *)input;
	stream.avail_in = (uInt)input_length;
	stream.next_out = *output;
	stream.avail_out = (uInt)capacity;
	result = deflate(&stream, Z_FINISH);
	*output_length = stream.total_out;
	deflateEnd(&stream);
	return result == Z_STREAM_END ? 0 : -1;
}

static void
test_gzip_and_limit(void)
{
	static const unsigned char plain[] =
	    "uma resposta HTTP comprimida para o Muninn mostrar como texto";
	struct capture_message_view message;
	struct body_decode_view decoded;
	unsigned char *compressed;
	size_t compressed_length;

	CHECK(make_gzip(plain, sizeof(plain) - 1, &compressed,
	    &compressed_length) == 0);
	memset(&message, 0, sizeof(message));
	message.body = compressed;
	message.body_len = compressed_length;
	(void)snprintf(message.content_encoding,
	    sizeof(message.content_encoding), "gzip");
	CHECK(body_decode(&message, 1024, &decoded) == 0);
	CHECK(decoded.status == BODY_DECODE_COMPLETE);
	CHECK(decoded.length == sizeof(plain) - 1);
	CHECK(memcmp(decoded.data, plain, decoded.length) == 0);
	CHECK(decoded.binary == 0);
	body_decode_free(&decoded);

	CHECK(body_decode(&message, 12, &decoded) == 0);
	CHECK(decoded.status == BODY_DECODE_LIMIT);
	CHECK(decoded.length == 12);
	body_decode_free(&decoded);
	free(compressed);
}

static void
test_deflate_and_brotli(void)
{
	static const unsigned char plain[] = "conteudo pequeno e legivel";
	struct capture_message_view message;
	struct body_decode_view decoded;
	unsigned char compressed[256];
	uLongf compressed_length;
	size_t brotli_length;

	memset(&message, 0, sizeof(message));
	compressed_length = sizeof(compressed);
	CHECK(compress2(compressed, &compressed_length, plain,
	    sizeof(plain) - 1, Z_BEST_COMPRESSION) == Z_OK);
	message.body = compressed;
	message.body_len = (size_t)compressed_length;
	(void)snprintf(message.content_encoding,
	    sizeof(message.content_encoding), "deflate");
	CHECK(body_decode(&message, 1024, &decoded) == 0);
	CHECK(decoded.status == BODY_DECODE_COMPLETE);
	CHECK(memcmp(decoded.data, plain, sizeof(plain) - 1) == 0);
	body_decode_free(&decoded);

	brotli_length = sizeof(compressed);
	CHECK(BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
	    BROTLI_MODE_TEXT, sizeof(plain) - 1, plain, &brotli_length,
	    compressed) == BROTLI_TRUE);
	message.body_len = brotli_length;
	(void)snprintf(message.content_encoding,
	    sizeof(message.content_encoding), "br");
	CHECK(body_decode(&message, 1024, &decoded) == 0);
	CHECK(decoded.status == BODY_DECODE_COMPLETE);
	CHECK(memcmp(decoded.data, plain, sizeof(plain) - 1) == 0);
	body_decode_free(&decoded);
}

static void
test_multiple_encodings(void)
{
	static const unsigned char plain[] = "duas camadas de compressao";
	struct capture_message_view message;
	struct body_decode_view decoded;
	unsigned char *gzip_data, *brotli_data;
	size_t brotli_capacity, brotli_length, gzip_length;

	gzip_data = NULL;
	brotli_data = NULL;
	if (make_gzip(plain, sizeof(plain) - 1, &gzip_data,
	    &gzip_length) == -1) {
		CHECK(0);
		return;
	}
	brotli_capacity = BrotliEncoderMaxCompressedSize(gzip_length);
	brotli_data = malloc(brotli_capacity);
	CHECK(brotli_data != NULL);
	if (brotli_data != NULL) {
		brotli_length = brotli_capacity;
		CHECK(BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY,
		    BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, gzip_length,
		    gzip_data, &brotli_length, brotli_data) == BROTLI_TRUE);
		memset(&message, 0, sizeof(message));
		message.body = brotli_data;
		message.body_len = brotli_length;
		(void)snprintf(message.content_encoding,
		    sizeof(message.content_encoding), "gzip, br");
		CHECK(body_decode(&message, 1024, &decoded) == 0);
		CHECK(decoded.status == BODY_DECODE_COMPLETE);
		CHECK(decoded.length == sizeof(plain) - 1);
		CHECK(memcmp(decoded.data, plain, decoded.length) == 0);
		body_decode_free(&decoded);
	}
	free(brotli_data);
	free(gzip_data);
}

static void
test_raw_and_unsupported(void)
{
	static unsigned char body[] = "raw";
	struct capture_message_view message;
	struct body_decode_view decoded;

	memset(&message, 0, sizeof(message));
	message.body = body;
	message.body_len = sizeof(body) - 1;
	CHECK(body_decode(&message, 1024, &decoded) == 0);
	CHECK(decoded.status == BODY_DECODE_RAW);
	CHECK(decoded.data == NULL);
	(void)snprintf(message.content_encoding,
	    sizeof(message.content_encoding), "zstd");
	CHECK(body_decode(&message, 1024, &decoded) == 0);
	CHECK(decoded.status == BODY_DECODE_UNSUPPORTED);
}

int
main(void)
{
	test_gzip_and_limit();
	test_deflate_and_brotli();
	test_multiple_encodings();
	test_raw_and_unsupported();
	if (failures != 0)
		return 1;
	puts("decode_test: ok");
	return 0;
}
