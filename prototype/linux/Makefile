CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11

all: aishield-proto aishieldd aishieldctl

aishield-proto: aishield.c
	$(CC) $(CFLAGS) -o $@ $<

aishieldd: aishieldd.c
	$(CC) $(CFLAGS) -o $@ $<

aishieldctl: aishieldctl.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f aishield-proto aishieldd aishieldctl
