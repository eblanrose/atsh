CC = clang
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS = -lutil -lssl -lcrypto
SRC = src

ifdef DEV_NOTLS
    CFLAGS += -DDEV_NOTLS
    LDFLAGS = -lutil
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    ifneq ($(shell getprop ro.product.cpu.abi 2>/dev/null),)
        LDFLAGS += -lcrypt -ltermux-auth
    else
        LDFLAGS += -lpam -lcrypt
    endif
endif

all: atshd atshc

atshd: $(SRC)/atshd.c $(SRC)/auth.c $(SRC)/crypto.c
	$(CC) $(CFLAGS) -o atshd $(SRC)/atshd.c $(SRC)/auth.c $(SRC)/crypto.c $(LDFLAGS)

atshc: $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c
	$(CC) $(CFLAGS) -o atshc $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c $(LDFLAGS)

clean:
	rm -f atshd atshc atsh.key atsh.crt

install: all
	cp atshd /usr/local/bin/
	cp atshc /usr/local/bin/
	chmod 755 /usr/local/bin/atshd /usr/local/bin/atshc
