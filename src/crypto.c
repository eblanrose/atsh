#include "crypto.h"
#include <string.h>
#include <stdlib.h>

static void derive_key(uint8_t key[32], uint32_t session_id, const char *password) {
    
    uint32_t state = session_id;
    for (int i = 0; i < 32; i++) {
        state = state * 1103515245 + 12345;
        key[i] = (uint8_t)(state ^ (password ? password[i % strlen(password)] : 0xAA));
    }
}

int atsh_crypto_init(void) { return 0; }
int atsh_crypto_server_init(const char *k, const char *c) { (void)k;(void)c; return 0; }


int atsh_crypto_client_init(ATSHCrypto *c, uint32_t session_id, const char *password) {
    if (!c) return -1;
    derive_key(c->key, session_id, password);
    c->handshake_done = 1;
    return 0;
}


int atsh_crypto_server_init_session(ATSHCrypto *c, uint32_t session_id, const char *password) {
    if (!c) return -1;
    derive_key(c->key, session_id, password);
    c->handshake_done = 1;
    return 0;
}

int atsh_encrypt_frame(ATSHCrypto *c, uint8_t type, const uint8_t *pt, size_t pt_len,
                       uint8_t **ct, size_t *ct_len) {
    (void)type;
    if (!c || !c->handshake_done) return -1;
    if (!pt || !pt_len) { *ct = NULL; *ct_len = 0; return 0; }
    
    *ct = malloc(pt_len);
    *ct_len = pt_len;
    for (size_t i = 0; i < pt_len; i++)
        (*ct)[i] = pt[i] ^ c->key[i % 32];
    return 0;
}

int atsh_decrypt_frame(ATSHCrypto *c, const uint8_t *ct, size_t ct_len,
                       uint8_t **pt, size_t *pt_len) {
    if (!c || !c->handshake_done) return -1;
    if (!ct || !ct_len) { *pt = NULL; *pt_len = 0; return 0; }
    
    
    return atsh_encrypt_frame(c, 0, ct, ct_len, pt, pt_len);
}

void atsh_crypto_wipe(ATSHCrypto *c) { 
    if (c) memset(c, 0, sizeof(*c)); 
}
