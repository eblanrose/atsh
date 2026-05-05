#ifndef ATSH_CRYPTO_H
#define ATSH_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t key[32];
    int handshake_done;
} ATSHCrypto;

int atsh_crypto_init(void);
int atsh_crypto_server_init(const char *key_file, const char *cert_file);
int atsh_crypto_client_init(ATSHCrypto *c, uint32_t session_id, const char *password);
int atsh_crypto_server_init_session(ATSHCrypto *c, uint32_t session_id, const char *password);
int atsh_encrypt_frame(ATSHCrypto *c, uint8_t type, const uint8_t *pt, size_t pt_len,
                       uint8_t **ct, size_t *ct_len);
int atsh_decrypt_frame(ATSHCrypto *c, const uint8_t *ct, size_t ct_len,
                       uint8_t **pt, size_t *pt_len);
void atsh_crypto_wipe(ATSHCrypto *c);

#endif
