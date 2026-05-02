CC ?= clang
CFLAGS ?= -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS ?= -lutil -lssl -lcrypto

ifdef DEV_NOTLS
    CFLAGS += -DDEV_NOTLS
    LDFLAGS = -lutil
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    ifneq ($(shell getprop ro.product.cpu.abi 2>/dev/null),)
        # Termux
        CFLAGS += -I$(CURDIR)/termux-auth
        LDFLAGS += -lcrypt
        TERMUX_AUTH_OBJ = termux-auth/termux-auth.o
    else
        # Desktop Linux
        LDFLAGS += -lpam -lcrypt
        TERMUX_AUTH_OBJ =
    endif
endif

ifeq ($(UNAME_S),FreeBSD)
    LDFLAGS += -lpam
endif

SRC = src

all: atshd atshc

# Сборка termux-auth.o только на Termux
termux-auth/termux-auth.o: termux-auth/termux-auth.c termux-auth/termux-auth.h
	$(CC) $(CFLAGS) -c -o $@ termux-auth/termux-auth.c

atshd: $(SRC)/atshd.c $(SRC)/auth.c $(SRC)/crypto.c $(TERMUX_AUTH_OBJ)
	$(CC) $(CFLAGS) -o atshd $(SRC)/atshd.c $(SRC)/auth.c $(SRC)/crypto.c $(TERMUX_AUTH_OBJ) $(LDFLAGS)

atshc: $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c $(TERMUX_AUTH_OBJ)
	$(CC) $(CFLAGS) -o atshc $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c $(TERMUX_AUTH_OBJ) $(LDFLAGS)

clean:
	rm -f atshd atshc atsh.key atsh.crt termux-auth/termux-auth.o

install: all
	cp atshd $(PREFIX)/bin/
	cp atshc $(PREFIX)/bin/
	chmod 755 $(PREFIX)/bin/atshd $(PREFIX)/bin/atshc

.PHONY: all clean install
