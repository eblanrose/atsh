CC ?= clang
CFLAGS ?= -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS ?= -lutil

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    ifneq ($(shell getprop ro.product.cpu.abi 2>/dev/null),)
        CFLAGS += -I$(CURDIR)/termux-auth
        LDFLAGS += -lcrypt -lssl -lcrypto
        TERMUX_AUTH_OBJ = termux-auth/termux-auth.o
    else
        LDFLAGS += -lpam -lcrypt
        TERMUX_AUTH_OBJ =
    endif
endif
ifeq ($(UNAME_S),FreeBSD)
    LDFLAGS += -lpam
endif

NAP_LIB = nap/libnotaproto.a
NAP_INC = -Inap -Inap/napc
SRC = src

all: atshd atshc

$(NAP_LIB):
	$(MAKE) -C nap

termux-auth/termux-auth.o: termux-auth/termux-auth.c termux-auth/termux-auth.h
	$(CC) $(CFLAGS) -lssl -lcrypto -c -o $@ termux-auth/termux-auth.c

atshd: $(NAP_LIB) $(SRC)/atshd.c $(SRC)/auth.c $(SRC)/crypto.c $(SRC)/tunnel.c $(TERMUX_AUTH_OBJ)
	$(CC) $(CFLAGS) $(NAP_INC) -o atshd $(SRC)/atshd.c $(SRC)/auth.c $(SRC)/crypto.c $(SRC)/tunnel.c $(TERMUX_AUTH_OBJ) $(NAP_LIB) $(LDFLAGS)

atshc: $(NAP_LIB) $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c $(TERMUX_AUTH_OBJ)
	$(CC) $(CFLAGS) $(NAP_INC) -o atshc $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c $(TERMUX_AUTH_OBJ) $(NAP_LIB) $(LDFLAGS)

clean:
	rm -f atshd atshc termux-auth/termux-auth.o
	$(MAKE) -C nap clean

install: all
	cp atshd $(PREFIX)/bin/
	cp atshc $(PREFIX)/bin/
	chmod 755 $(PREFIX)/bin/atshd $(PREFIX)/bin/atshc

.PHONY: all clean install
