CC = cc
FUZZ_CC ?= clang
CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -Wextra -Wpedantic -g
VERSION = 0.1.0
CPPFLAGS = -Iinclude -DMUNINN_VERSION='"${VERSION}"'
LDLIBS = -lncurses -lssl -lcrypto -lz -lbrotlidec -pthread

PREFIX ?= /usr/local
DESTDIR ?=
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/share/man/man1
INSTALL ?= install

PROGRAM = muninn
BUILD_DIR = build
SRCS = src/main.c src/config.c src/capture.c src/decode.c src/util.c \
       src/tui_view.c src/tui.c src/net.c src/http.c src/http_observer.c \
       src/tls.c src/relay.c src/proxy.c
OBJS = ${SRCS:src/%.c=${BUILD_DIR}/%.o}
DEPS = ${OBJS:.o=.d}
TEST_PROGRAMS = ${BUILD_DIR}/http_parser_test ${BUILD_DIR}/config_test \
                ${BUILD_DIR}/tls_test ${BUILD_DIR}/capture_test \
                ${BUILD_DIR}/tui_view_test ${BUILD_DIR}/decode_test \
                ${BUILD_DIR}/capture_concurrency_test

.DEFAULT_GOAL := all

all: ${PROGRAM}

${PROGRAM}: ${OBJS}
	${CC} ${CFLAGS} ${OBJS} ${LDLIBS} -o $@

ready: all

install: ${PROGRAM}
	${INSTALL} -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}
	${INSTALL} -m 755 ${PROGRAM} ${DESTDIR}${BINDIR}/${PROGRAM}
	${INSTALL} -m 644 docs/muninn.1 ${DESTDIR}${MANDIR}/muninn.1

uninstall:
	rm -f ${DESTDIR}${BINDIR}/${PROGRAM}
	rm -f ${DESTDIR}${MANDIR}/muninn.1

${BUILD_DIR}/%.o: src/%.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} -MMD -MP -c $< -o $@

${BUILD_DIR}/tui.o ${BUILD_DIR}/tui_view.o: include/tui_view.h include/capture.h
${BUILD_DIR}/tui.o ${BUILD_DIR}/decode.o: include/decode.h

${BUILD_DIR}:
	mkdir -p $@

clean:
	rm -rf ${BUILD_DIR}
	rm -f ${PROGRAM}

check: ${TEST_PROGRAMS}
	./${BUILD_DIR}/http_parser_test
	./${BUILD_DIR}/config_test
	./${BUILD_DIR}/tls_test
	./${BUILD_DIR}/capture_test
	./${BUILD_DIR}/tui_view_test
	./${BUILD_DIR}/decode_test
	./${BUILD_DIR}/capture_concurrency_test

${BUILD_DIR}/http_parser_test: tests/http_parser_test.c \
    src/http_observer.c src/capture.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/http_parser_test.c \
	    src/http_observer.c src/capture.c -pthread -o $@

${BUILD_DIR}/config_test: tests/config_test.c src/config.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/config_test.c src/config.c -o $@

${BUILD_DIR}/tls_test: tests/tls_test.c src/tls.c src/config.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/tls_test.c src/tls.c src/config.c \
	    -lssl -lcrypto -pthread -o $@

${BUILD_DIR}/capture_test: tests/capture_test.c src/capture.c include/capture.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/capture_test.c src/capture.c \
	    -pthread -o $@

${BUILD_DIR}/tui_view_test: tests/tui_view_test.c src/tui_view.c \
    include/tui_view.h include/capture.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/tui_view_test.c src/tui_view.c -o $@

${BUILD_DIR}/decode_test: tests/decode_test.c src/decode.c include/decode.h \
    include/capture.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/decode_test.c src/decode.c \
	    -lz -lbrotlidec -lbrotlienc -o $@

${BUILD_DIR}/capture_concurrency_test: tests/capture_concurrency_test.c \
    src/capture.c include/capture.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/capture_concurrency_test.c \
	    src/capture.c -pthread -o $@

${BUILD_DIR}/http_parser_fuzz: tests/http_parser_fuzz.c src/http_observer.c \
    src/capture.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} -DFUZZ_STANDALONE \
	    tests/http_parser_fuzz.c src/http_observer.c src/capture.c \
	    -pthread -o $@

fuzz-smoke: ${BUILD_DIR}/http_parser_fuzz
	printf 'GET / HTTP/1.1\r\nHost: fuzz.test\r\n\r\n' | ./${BUILD_DIR}/http_parser_fuzz
	printf 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest' | ./${BUILD_DIR}/http_parser_fuzz
	printf '\000\377invalid\r\nchunk' | ./${BUILD_DIR}/http_parser_fuzz

fuzz-http: | ${BUILD_DIR}
	${FUZZ_CC} ${CPPFLAGS} ${CFLAGS} -fsanitize=fuzzer,address,undefined \
	    tests/http_parser_fuzz.c src/http_observer.c src/capture.c \
	    -pthread -o ${BUILD_DIR}/http_parser_fuzzer
	./${BUILD_DIR}/http_parser_fuzzer

sanitize:
	${MAKE} BUILD_DIR=${BUILD_DIR}/sanitize \
	    CFLAGS='${CFLAGS} -fsanitize=address,undefined -fno-omit-frame-pointer' \
	    check

thread-sanitize:
	${MAKE} BUILD_DIR=${BUILD_DIR}/thread-sanitize \
	    CFLAGS='${CFLAGS} -fsanitize=thread -fno-omit-frame-pointer' \
	    ${BUILD_DIR}/thread-sanitize/capture_concurrency_test
	./${BUILD_DIR}/thread-sanitize/capture_concurrency_test

-include ${DEPS}

.PHONY: all ready install uninstall clean check fuzz-smoke fuzz-http sanitize thread-sanitize
