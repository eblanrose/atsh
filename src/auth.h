#ifndef ATSH_AUTH_H
#define ATSH_AUTH_H
#include <stdint.h>
#include <stddef.h>
typedef enum {
    ATSH_AUTH_OK = 0,
    ATSH_AUTH_FAIL = -1,
    ATSH_AUTH_ERROR = -2,
} ATSHAuthResult;
typedef int (*atsh_password_cb)(const char *prompt, char *buf, size_t len);
int atsh_auth_init(void);
int atsh_auth_verify(const char *username, const char *password);
int atsh_auth_prompt(const char *username, char *password, size_t len,
                     atsh_password_cb cb);
void atsh_auth_wipe_password(char *password, size_t len);
#endif // ATSH_AUTH_H
