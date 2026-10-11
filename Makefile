CC ?= cc
CFLAGS += -g -Wall -Wextra -O2

all: libamt.a

libamt.a: amt.o
	ar rcs $@ amt.o

amt.o: amt.c amt.h

clean:
	rm -f libamt.a amt.o

# Linux-only: exercises amt.c end-to-end across a real veth link between
# two network namespaces (one as gateway, one as AMT relay). Needs root.
test-amt-netns:
	sudo tests/run_netns_test.sh

test-amt-netns-rust:
	sudo tests/run_netns_test_rust.sh

.PHONY: all clean test-amt-netns
