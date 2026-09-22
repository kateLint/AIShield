CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11

all: aishield-proto

aishield-proto: aishield.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f aishield-proto
