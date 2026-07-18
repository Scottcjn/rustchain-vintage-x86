# RustChain vintage x86 miner
#
# Native build on the vintage box (correct for its own kernel + libc):
#   make
#
# The default flags are deliberately conservative so ancient gcc (2.7 - 3.x)
# and old glibc accept them. If your gcc is very old and chokes on a flag,
# fall back to the bare compile line printed below.

CC      ?= gcc
CFLAGS  ?= -O2
TARGET   = rustchain_cobalt
SRC      = rustchain_cobalt_miner.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# If make or the flags above fail on a truly ancient toolchain, this always works:
bare:
	$(CC) -o $(TARGET) $(SRC)

test: $(TARGET)
	./$(TARGET) --self-test

clean:
	rm -f $(TARGET)

.PHONY: all bare test clean
