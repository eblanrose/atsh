CC ?= clang
CFLAGS ?= -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -flto -fdata-sections -ffunction-sections
LDFLAGS ?= -Wl,--gc-sections -s

UNAME_S := $(shell uname -s)

# Определение libc типа
LIBC_TYPE := $(shell ldd --version 2>&1 | grep -qi musl && echo "musl" || echo "glibc")

# Общие флаги
CFLAGS += -D_POSIX_C_SOURCE=200809L

# Платформозависимые настройки
ifeq ($(UNAME_S),Linux)
    CFLAGS += -D__LINUX__
    ifneq ($(shell getprop ro.product.cpu.abi 2>/dev/null),)
        # Termux (Android)
        CFLAGS += -I$(CURDIR)/termux-auth
        LDFLAGS += -lcrypt -lssl -lcrypto
        TERMUX_AUTH_OBJ = termux-auth/termux-auth.o
    else
        # Обычный Linux
        ifeq ($(LIBC_TYPE),musl)
            CFLAGS += -D__MUSL__
            LDFLAGS += -lutil -lcrypt -lssl -lcrypto -lbsd
        else
            LDFLAGS += -lpam -lutil -lcrypt -lssl -lcrypto
        endif
        TERMUX_AUTH_OBJ =
    endif
endif

ifeq ($(UNAME_S),FreeBSD)
    CFLAGS += -D__FREEBSD__
    LDFLAGS += -lutil -lpam
    TERMUX_AUTH_OBJ =
endif

ifeq ($(UNAME_S),Darwin)
    CFLAGS += -D__DARWIN__
    LDFLAGS += -lutil
    TERMUX_AUTH_OBJ =
endif

# Оптимизация для размера
ifdef DEBUG
    CFLAGS := -Wall -Wextra -O0 -g -std=c11 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
    LDFLAGS :=
else
    CFLAGS += -DNDEBUG
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

atshc: $(NAP_LIB) $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c $(SRC)/tunnel_client.c $(TERMUX_AUTH_OBJ)
	$(CC) $(CFLAGS) $(NAP_INC) -o atshc $(SRC)/atshc.c $(SRC)/auth.c $(SRC)/crypto.c $(SRC)/tunnel_client.c $(TERMUX_AUTH_OBJ) $(NAP_LIB) $(LDFLAGS) -lpthread

clean:
	rm -f atshd atshc termux-auth/termux-auth.o
	$(MAKE) -C nap clean

distclean: clean
	rm -f cppcheck_report.txt

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 atshd $(DESTDIR)$(PREFIX)/bin/
	install -m 755 atshc $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/atshd
	rm -f $(DESTDIR)$(PREFIX)/bin/atshc

cppcheck:
	cppcheck --enable=all --inconclusive --std=c11 \
	         --suppress=missingIncludeSystem \
	         --suppress=unusedFunction \
	         --suppress=constVariablePointer \
	         --suppress=constParameter \
	         src/ 2>&1 | tee cppcheck_report.txt

valgrind: atshd
	valgrind --leak-check=full --show-leak-kinds=all ./atshd -p 2811

.PHONY: all clean install uninstall cppcheck valgrind distclean
