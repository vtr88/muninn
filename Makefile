CC = cc
CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -Wextra -Wpedantic -g
CPPFLAGS = -Iinclude
LDLIBS = -lncurses -lssl -lcrypto -pthread

PROGRAM = muninn
BIN_DIR = bin
BUILD_DIR = build
SRCS = src/main.c src/config.c src/util.c src/tui.c src/net.c src/http.c \
       src/http_observer.c src/tls.c src/relay.c src/proxy.c
OBJS = ${SRCS:src/%.c=${BUILD_DIR}/%.o}
TEST_PROGRAMS = ${BUILD_DIR}/http_parser_test ${BUILD_DIR}/config_test \
                ${BUILD_DIR}/tls_test

.DEFAULT_GOAL := all

all: ${PROGRAM}

${PROGRAM}: ${OBJS}
	${CC} ${CFLAGS} ${OBJS} ${LDLIBS} -o $@

ready: ${BIN_DIR}/${PROGRAM}

${BIN_DIR}/${PROGRAM}: ${OBJS} | ${BIN_DIR}
	${CC} ${CFLAGS} ${OBJS} ${LDLIBS} -o $@
	@rm -f ${PROGRAM}

${BUILD_DIR}/%.o: src/%.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} -c $< -o $@

${BUILD_DIR} ${BIN_DIR}:
	mkdir -p $@

clean:
	rm -rf ${BUILD_DIR} ${BIN_DIR}
	rm -f ${PROGRAM}

check: ${TEST_PROGRAMS}
	./${BUILD_DIR}/http_parser_test
	./${BUILD_DIR}/config_test
	./${BUILD_DIR}/tls_test

${BUILD_DIR}/http_parser_test: tests/http_parser_test.c src/http_observer.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/http_parser_test.c \
	    src/http_observer.c -o $@

${BUILD_DIR}/config_test: tests/config_test.c src/config.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/config_test.c src/config.c -o $@

${BUILD_DIR}/tls_test: tests/tls_test.c src/tls.c src/config.c include/muninn.h | ${BUILD_DIR}
	${CC} ${CPPFLAGS} ${CFLAGS} tests/tls_test.c src/tls.c src/config.c \
	    -lssl -lcrypto -pthread -o $@

.PHONY: all ready clean check
