OBJS = muninn.c
CC = cc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g
LDLIBS = -lncurses -lssl -lcrypto -pthread
OBJ_NAME = muninn
BIN_DIR = bin

.DEFAULT_GOAL := all

# Target to create the binary in bin directory
ready: $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJS) $(LDLIBS) -o $(BIN_DIR)/$(OBJ_NAME)
	@rm -f $(OBJ_NAME)

clean:
	@rm -rf $(BIN_DIR)
	@rm -f $(OBJ_NAME)

# Target to create the binary in the current directory
all: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDLIBS) -o $(OBJ_NAME)

.PHONY: all ready clean
