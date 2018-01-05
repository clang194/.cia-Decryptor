CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Wpedantic -O2
CPPFLAGS ?= -D_FILE_OFFSET_BITS=64
LDFLAGS ?=

BIN := cia-decrypt
SRC := tool.c portable.c vault.c content_stream.c package_flow.c aes.c sha256.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

test: $(BIN)
	./$(BIN) --self-test

clean:
	rm -f $(BIN) $(OBJ)
