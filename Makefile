OBJS = muninn.c

#CC specifies which compiler we're using
CC = gcc

#COMPILER_FLAGS specifies the additional compilation options we're using
# -w suppresses all warnings
COMPILER_FLAGS = -w -g -std=gnu99 #gnu99 for posix??

#LINKER_FLAGS specifies the libraries we're linking against
LINKER_FLAGS = -lssl -lcrypto

#OBJ_NAME specifies the name of our exectuable
OBJ_NAME = muninn

# Directory for the binary
BIN_DIR = bin

.DEFAULT_GOAL := all

# Target to create the binary in bin directory
ready: $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJS) $(COMPILER_FLAGS) $(LINKER_FLAGS) -o $(BIN_DIR)/$(OBJ_NAME)
	@rm -f $(OBJ_NAME)

# Target to create the binary in the current directory
all: $(OBJS)
	$(CC) $(OBJS) $(COMPILER_FLAGS) $(LINKER_FLAGS) -o $(OBJ_NAME)

.PHONY: all ready
