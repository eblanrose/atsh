
#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <termios.h>
#include <crypt.h>

#ifndef explicit_bzero
#define explicit_bzero(p, n) do { volatile char *__p = (volatile char *)(p); size_t __n = (n); while(__n--) *__p++ = 0; } while(0)
#endif

#if defined(__ANDROID__)

    #include <termux-auth.h>
#elif defined(__linux__)

    #include <security/pam_appl.h>
#else

#endif

#if defined(__linux__) && !defined(__ANDROID__)

typedef struct {
    const char *password;
} pam_auth_data_t;

static int pam_conversation(int num_msg, const struct pam_message **msg,
                           struct pam_response **resp, void *appdata) {
    pam_auth_data_t *data = (pam_auth_data_t *)appdata;
    *resp = calloc((size_t)num_msg, sizeof(struct pam_response));
    if (!*resp) return PAM_CONV_ERR;
    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
            msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            (*resp)[i].resp = strdup(data->password);
            if (!(*resp)[i].resp) {
                for (int j = 0; j < i; j++) free((*resp)[j].resp);
                free(*resp);
                return PAM_CONV_ERR;
            }
        }
    }
    return PAM_SUCCESS;
}

int atsh_auth_verify(const char *username, const char *password) {
    if (!username || !password) return ATSH_AUTH_ERROR;
    if (strlen(password) == 0) return ATSH_AUTH_FAIL;

    pam_handle_t *pamh = NULL;
    pam_auth_data_t data = { .password = password };
    struct pam_conv conv = { pam_conversation, &data };

    int ret = pam_start("atsh", username, &conv, &pamh);
    if (ret != PAM_SUCCESS) ret = pam_start("login", username, &conv, &pamh);
    if (ret != PAM_SUCCESS) return ATSH_AUTH_ERROR;

    ret = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    if (ret != PAM_SUCCESS) { pam_end(pamh, ret); return ATSH_AUTH_FAIL; }

    ret = pam_acct_mgmt(pamh, 0);
    pam_end(pamh, ret);
    return (ret == PAM_SUCCESS) ? ATSH_AUTH_OK : ATSH_AUTH_FAIL;
}

#elif defined(__ANDROID__)

int atsh_auth_verify(const char *username, const char *password) {
    if (!username || !password) return ATSH_AUTH_ERROR;
    if (strlen(password) == 0) return ATSH_AUTH_FAIL;

    return termux_auth(username, password) ? ATSH_AUTH_OK : ATSH_AUTH_FAIL;
}

#else

int atsh_auth_verify(const char *username, const char *password) {
    if (!username || !password) return ATSH_AUTH_ERROR;

    struct passwd *pw = getpwnam(username);
    if (!pw) return ATSH_AUTH_FAIL;

    if (pw->pw_passwd && strlen(pw->pw_passwd) >= 13) {
        char *hash = crypt(password, pw->pw_passwd);
        if (hash && strcmp(hash, pw->pw_passwd) == 0)
            return ATSH_AUTH_OK;
    }

    return ATSH_AUTH_FAIL;
}

#endif

int atsh_auth_init(void) { return 0; }

int atsh_auth_prompt(const char *username, char *password, size_t len,
                     atsh_password_cb cb) {
    if (!password || len == 0) return -1;

    printf("Password: ");
    fflush(stdout);

    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    if (!fgets(password, (int)len, stdin)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        return -1;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
    password[strcspn(password, "\r\n")] = '\0';

    return (int)strlen(password);
}

void atsh_auth_wipe_password(char *password, size_t len) {
    if (password && len > 0) {
        explicit_bzero(password, len);
    }
}
