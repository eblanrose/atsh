CC = clang
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS = -lutil

ifdef TURNOFFCRYPTO
    CFLAGS += -DTURNOFFCRYPTO
else
    LDFLAGS += -lssl -lcrypto
endif

UNAME_S := $(shell uname -s)
ANDROID_ABI := $(shell getprop ro.product.cpu.abi 2>/dev/null)

ifeq ($(UNAME_S),Linux)
ifneq ($(ANDROID_ABI),)
    LDFLAGS += -lcrypt -ltermux-auth
else
    LDFLAGS += -lpam -lcrypt
endif
endif

.PHONY: all cert clean

all: atshd atshc

atshd: src/atshd.c src/auth.c src/crypto.c src/tunnel.c
	$(CC) $(CFLAGS) -o $@ src/atshd.c src/auth.c src/crypto.c src/tunnel.c $(LDFLAGS)

atshc: src/atshc.c src/auth.c src/crypto.c
	$(CC) $(CFLAGS) -o $@ src/atshc.c src/auth.c src/crypto.c $(LDFLAGS)

cert:
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-nodes -keyout atsh.key -out atsh.crt -days 3650 -subj "/CN=ATSH-Server"

clean:
	rm -f atshd atshc atsh.key atsh.crt
