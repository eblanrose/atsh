#ifndef ATSH_CRYPTO_H
#define ATSH_CRYPTO_H
#include <stdint.h>
#include <stddef.h>
#ifdef DEV_NOTLS
typedef struct { int handshake_done; } ATSHCrypto;
#else
#include <openssl/ssl.h>
typedef struct { SSL_CTX *ctx; SSL *ssl; int handshake_done; } ATSHCrypto;
#endif
int atsh_crypto_init(void);
int atsh_crypto_server_init(const char *key_file, const char *cert_file);
int atsh_handshake_client(ATSHCrypto *c, int fd, const char *host);
int atsh_handshake_server(ATSHCrypto *c, int fd);
int atsh_send_frame(ATSHCrypto *c, int fd, uint8_t type, const uint8_t *data, size_t len);
int atsh_recv_frame(ATSHCrypto *c, int fd, uint8_t *type, uint8_t **data, size_t *len);
void atsh_crypto_wipe(ATSHCrypto *c);
int atsh_tofu_check(const char *host, const uint8_t *fp, size_t len);
int atsh_tofu_save(const char *host, const uint8_t *fp, size_t len);
#endif
