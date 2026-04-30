#include <unistd.h>
#include "crypto.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef TURNOFFCRYPTO

int atsh_crypto_init(void) { return 0; }

int atsh_handshake_client(ATSHCrypto *ctx, int fd) {
    (void)fd;
    ctx->handshake_done = 1;
    ctx->is_server = 0;
    return 0;
}

int atsh_handshake_server(ATSHCrypto *ctx, int fd, const ATSHKeyPair *master) {
    (void)fd; (void)master;
    ctx->handshake_done = 1;
    ctx->is_server = 1;
    return 0;
}

int atsh_send_frame(ATSHCrypto *ctx, int fd, uint8_t type, const uint8_t *data, size_t len) {
    (void)ctx;
    ATSHHeader hdr = { .version = ATSH_VERSION_MAJOR, .type = type,
                       .reserved = 0, .payload_size = (uint32_t)len };
    if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) return -1;
    if (data && len > 0) {
        size_t tot = 0;
        while (tot < len) {
            ssize_t n = write(fd, data + tot, len - tot);
            if (n <= 0) return -1;
            tot += (size_t)n;
        }
    }
    return 0;
}

int atsh_recv_frame(ATSHCrypto *ctx, int fd, uint8_t *type, uint8_t **data, size_t *len) {
    (void)ctx;
    ATSHHeader hdr;
    size_t tot = 0;
    while (tot < sizeof(hdr)) {
        ssize_t n = read(fd, (uint8_t*)&hdr + tot, sizeof(hdr) - tot);
        if (n <= 0) return -1;
        tot += (size_t)n;
    }
    *type = hdr.type;
    *len = hdr.payload_size;
    if (*len > 0) {
        *data = malloc(*len);
        if (!*data) return -1;
        tot = 0;
        while (tot < *len) {
            ssize_t n = read(fd, *data + tot, *len - tot);
            if (n <= 0) { free(*data); return -1; }
            tot += (size_t)n;
        }
    } else {
        *data = NULL;
    }
    return 0;
}

void atsh_crypto_wipe(ATSHCrypto *ctx) {
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

#else

int atsh_crypto_init(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif
    return 0;
}

int atsh_handshake_client(ATSHCrypto *ctx, int fd) {
    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx) { ERR_print_errors_fp(stderr); return -1; }

    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);

    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    SSL_set_fd(ctx->ssl, fd);

    if (SSL_connect(ctx->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    ctx->handshake_done = 1;
    return 0;
}

int atsh_handshake_server(ATSHCrypto *ctx, int fd, const ATSHKeyPair *master) {
    (void)master;

    ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx->ssl_ctx) { ERR_print_errors_fp(stderr); return -1; }

    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);

    if (!SSL_CTX_use_certificate_file(ctx->ssl_ctx, "atsh.crt", SSL_FILETYPE_PEM)) {
        fprintf(stderr, "Failed to load atsh.crt\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, "atsh.key", SSL_FILETYPE_PEM)) {
        fprintf(stderr, "Failed to load atsh.key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    SSL_set_fd(ctx->ssl, fd);

    if (SSL_accept(ctx->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    ctx->handshake_done = 1;
    return 0;
}

int atsh_send_frame(ATSHCrypto *ctx, int fd, uint8_t type, const uint8_t *data, size_t len) {
    (void)fd;
    if (!ctx || !ctx->handshake_done) return -1;

    ATSHHeader hdr = { .version = ATSH_VERSION_MAJOR, .type = type,
                       .reserved = 0, .payload_size = (uint32_t)len };

    if (SSL_write(ctx->ssl, &hdr, sizeof(hdr)) != sizeof(hdr)) return -1;
    if (data && len > 0) {
        if (SSL_write(ctx->ssl, data, (int)len) != (int)len) return -1;
    }
    return 0;
}

int atsh_recv_frame(ATSHCrypto *ctx, int fd, uint8_t *type, uint8_t **data, size_t *len) {
    (void)fd;
    if (!ctx || !ctx->handshake_done) return -1;

    ATSHHeader hdr;
    if (SSL_read(ctx->ssl, &hdr, sizeof(hdr)) != sizeof(hdr)) return -1;

    *type = hdr.type;
    *len = hdr.payload_size;

    if (*len > 0) {
        *data = malloc(*len);
        if (!*data) return -1;
        if (SSL_read(ctx->ssl, *data, (int)*len) != (int)*len) {
            free(*data);
            return -1;
        }
    } else {
        *data = NULL;
    }
    return 0;
}

void atsh_crypto_wipe(ATSHCrypto *ctx) {
    if (!ctx) return;
    if (ctx->ssl) { SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); ctx->ssl = NULL; }
    if (ctx->ssl_ctx) { SSL_CTX_free(ctx->ssl_ctx); ctx->ssl_ctx = NULL; }
    memset(ctx, 0, sizeof(*ctx));
}

#endif
