#ifndef ATSH_CRYPTO_H
#define ATSH_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef TURNOFFCRYPTO
typedef struct {
    int handshake_done;
    int is_server;
} ATSHCrypto;

#define ATSH_PUBKEY_SIZE 32
#define ATSH_SECKEY_SIZE 32

typedef struct {
    uint8_t public_key[ATSH_PUBKEY_SIZE];
    uint8_t secret_key[ATSH_SECKEY_SIZE];
} ATSHKeyPair;

#else
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int handshake_done;
} ATSHCrypto;

#define ATSH_PUBKEY_SIZE 32
#define ATSH_SECKEY_SIZE 32

typedef struct {
    uint8_t public_key[ATSH_PUBKEY_SIZE];
    uint8_t secret_key[ATSH_SECKEY_SIZE];
} ATSHKeyPair;

#endif

int atsh_crypto_init(void);
int atsh_handshake_client(ATSHCrypto *ctx, int fd);
int atsh_handshake_server(ATSHCrypto *ctx, int fd, const ATSHKeyPair *master);
int atsh_send_frame(ATSHCrypto *ctx, int fd, uint8_t type, const uint8_t *data, size_t len);
int atsh_recv_frame(ATSHCrypto *ctx, int fd, uint8_t *type, uint8_t **data, size_t *len);
void atsh_crypto_wipe(ATSHCrypto *ctx);

#endif
