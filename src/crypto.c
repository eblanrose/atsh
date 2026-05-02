
#include "crypto.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#ifdef DEV_NOTLS

#warning "DEV_NOTLS: encryption disabled"
int atsh_crypto_init(void) { return 0; }
int atsh_crypto_server_init(const char *k, const char *c) { (void)k;(void)c; return 0; }
int atsh_handshake_client(ATSHCrypto *c, int fd, const char *h) { (void)fd;(void)h; c->handshake_done=1; return 0; }
int atsh_handshake_server(ATSHCrypto *c, int fd) { (void)fd; c->handshake_done=1; return 0; }
int atsh_send_frame(ATSHCrypto *c, int fd, uint8_t type, const uint8_t *data, size_t len) {
    (void)c;
    ATSHHeader h = {.version=ATSH_VERSION_MAJOR,.type=type,.reserved=0,.payload_size=(uint32_t)len};
    if (write(fd,&h,sizeof(h))!=sizeof(h)) return -1;
    if (data&&len) { size_t t=0; while(t<len) { ssize_t n=write(fd,data+t,len-t); if(n<=0)return -1; t+=n; } }
    return 0;
}
int atsh_recv_frame(ATSHCrypto *c, int fd, uint8_t *type, uint8_t **data, size_t *len) {
    (void)c;
    ATSHHeader h; size_t t=0;
    while(t<sizeof(h)){ssize_t n=read(fd,(uint8_t*)&h+t,sizeof(h)-t); if(n<=0)return -1; t+=n;}
    *type=h.type; *len=h.payload_size;
    if(*len){*data=malloc(*len); if(!*data)return -1; t=0; while(t<*len){ssize_t n=read(fd,*data+t,*len-t); if(n<=0){free(*data);return -1;}t+=n;}}
    else *data=NULL;
    return 0;
}
void atsh_crypto_wipe(ATSHCrypto *c) { if(c)memset(c,0,sizeof(*c)); }
#else

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
int atsh_crypto_init(void) { return 0; }
int atsh_crypto_server_init(const char *key_file, const char *cert_file) {
    if (access(key_file, F_OK) == 0 && access(cert_file, F_OK) == 0) return 0;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "
        "-nodes -keyout %s -out %s -days 3650 -subj '/CN=%s' 2>/dev/null",
        key_file, cert_file, "ATSH-Server");
    int ret = system(cmd);
    if (ret != 0) { fprintf(stderr, "Key generation failed\n"); return -1; }
    printf("[Crypto] Generated %s, %s\n", key_file, cert_file);
    return 0;
}
int atsh_handshake_client(ATSHCrypto *c, int fd, const char *host) {
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) { ERR_print_errors_fp(stderr); return -1; }
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_3_VERSION);
    

    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);
    
    c->ssl = SSL_new(c->ctx);
    SSL_set_fd(c->ssl, fd);
    SSL_set_tlsext_host_name(c->ssl, host);
    
    if (SSL_connect(c->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    

    X509 *cert = SSL_get_peer_certificate(c->ssl);
    if (!cert) {
        fprintf(stderr, "No server certificate\n");
        return -1;
    }
    
    uint8_t fp[EVP_MAX_MD_SIZE];
    unsigned int fp_len;
    X509_digest(cert, EVP_sha256(), fp, &fp_len);
    
    int r = atsh_tofu_check(host, fp, fp_len);
    
    if (r == 0) {

        printf("[TOFU] New host key for %s\nSHA256: ", host);
        for (unsigned int i = 0; i < fp_len; i++) printf("%02x", fp[i]);
        printf("\nAccept? [yes/no]: ");
        fflush(stdout);
        
        char a[32];
        if (fgets(a, sizeof(a), stdin) && !strncmp(a, "yes", 3)) {
            atsh_tofu_save(host, fp, fp_len);
            printf("[TOFU] Saved\n");
        } else {
            fprintf(stderr, "Host key rejected\n");
            X509_free(cert);
            return -1;
        }
    } else if (r == 1) {

        printf("[TOFU] Host key verified\n");
    } else {

        fprintf(stderr, "WARNING: Host key for %s changed!\n", host);
        fprintf(stderr, "SHA256: ");
        for (unsigned int i = 0; i < fp_len; i++) fprintf(stderr, "%02x", fp[i]);
        fprintf(stderr, "\nPossible MITM attack!\n");
        X509_free(cert);
        return -1;
    }
    
    X509_free(cert);
    c->handshake_done = 1;
    return 0;
}
int atsh_handshake_server(ATSHCrypto *c, int fd) {
    c->ctx = SSL_CTX_new(TLS_server_method());
    if (!c->ctx) { ERR_print_errors_fp(stderr); return -1; }
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_3_VERSION);
    if (!SSL_CTX_use_certificate_file(c->ctx, "atsh.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(c->ctx, "atsh.key", SSL_FILETYPE_PEM)) {
        fprintf(stderr, "Failed to load cert/key\n"); return -1;
    }
    c->ssl = SSL_new(c->ctx);
    SSL_set_fd(c->ssl, fd);
    if (SSL_accept(c->ssl) <= 0) { ERR_print_errors_fp(stderr); return -1; }
    c->handshake_done = 1;
    return 0;
}
int atsh_send_frame(ATSHCrypto *c, int fd, uint8_t type, const uint8_t *data, size_t len) {
    (void)fd;
    if (!c||!c->handshake_done) return -1;
    ATSHHeader h = {.version=ATSH_VERSION_MAJOR,.type=type,.reserved=0,.payload_size=(uint32_t)len};
    if (SSL_write(c->ssl,&h,sizeof(h))!=sizeof(h)) return -1;
    if (data&&len&&SSL_write(c->ssl,data,(int)len)!=(int)len) return -1;
    return 0;
}
int atsh_recv_frame(ATSHCrypto *c, int fd, uint8_t *type, uint8_t **data, size_t *len) {
    (void)fd;
    if (!c||!c->handshake_done) return -1;
    ATSHHeader h;
    if (SSL_read(c->ssl,&h,sizeof(h))!=sizeof(h)) return -1;
    *type=h.type; *len=h.payload_size;
    if (*len) { *data=malloc(*len); if(!*data)return -1; if(SSL_read(c->ssl,*data,(int)*len)!=(int)*len){free(*data);return -1;} }
    else *data=NULL;
    return 0;
}
void atsh_crypto_wipe(ATSHCrypto *c) {
    if (!c) return;
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    if (c->ctx) SSL_CTX_free(c->ctx);
    memset(c,0,sizeof(*c));
}

int atsh_tofu_check(const char *host, const uint8_t *fp, size_t len) {
    char path[512], fp_hex[EVP_MAX_MD_SIZE*2+1];
    const char *home = getenv("HOME") ?: ".";
    snprintf(path, sizeof(path), "%s/.atsh", home);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/.atsh/known_hosts", home);
    
    for (size_t i=0;i<len;i++) sprintf(fp_hex+i*2,"%02x",fp[i]);
    fp_hex[len*2]='\0';
    
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    while (fgets(line,sizeof(line),f)) {
        char h[256], s[EVP_MAX_MD_SIZE*2+1];
        if (sscanf(line,"%s %s",h,s)==2 && !strcmp(h,host)) { fclose(f); return strcmp(s,fp_hex)?2:1; }
    }
    fclose(f);
    return 0;
}
int atsh_tofu_save(const char *host, const uint8_t *fp, size_t len) {
    char path[512];
    const char *home = getenv("HOME") ?: ".";
    snprintf(path, sizeof(path), "%s/.atsh", home);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/.atsh/known_hosts", home);
    
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    fprintf(f, "%s ", host);
    for (size_t i=0;i<len;i++) fprintf(f,"%02x",fp[i]);
    fprintf(f, "\n");
    fclose(f);
    return 0;
}
#endif
