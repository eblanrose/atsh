
#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <termios.h>
#include <crypt.h>
#include <time.h>
#ifndef explicit_bzero
#define explicit_bzero(p,n) do{volatile char*_p=(volatile char*)(p);size_t _n=(n);while(_n--)*_p++=0;}while(0)
#endif
#if defined(__ANDROID__)
#include <termux-auth.h>
#elif defined(__linux__)
#include <security/pam_appl.h>
#endif

static time_t g_fail_time = 0;
static int g_fail_count = 0;
static int anti_bruteforce_wait(void) {
    time_t now = time(NULL);
    if (g_fail_time == 0) return 0;
    
    int delay = (1 << g_fail_count);  // exponential: 1,2,4,8,16...
    if (delay > 60) delay = 60;
    
    time_t elapsed = now - g_fail_time;
    if (elapsed < delay) {
        sleep(delay - elapsed);
    }
    
    return 0;
}
static void anti_bruteforce_fail(void) {
    g_fail_time = time(NULL);
    g_fail_count++;
}
static void anti_bruteforce_success(void) {
    g_fail_time = 0;
    g_fail_count = 0;
}

#if defined(__linux__) && !defined(__ANDROID__)
typedef struct { const char *password; } pam_data_t;
static int pam_conv_fn(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
    pam_data_t *d = data;
    *resp = calloc(n, sizeof(struct pam_response));
    if (!*resp) return PAM_CONV_ERR;
    for (int i=0;i<n;i++) {
        if (msg[i]->msg_style==PAM_PROMPT_ECHO_OFF||msg[i]->msg_style==PAM_PROMPT_ECHO_ON)
            (*resp)[i].resp = strdup(d->password);
    }
    return PAM_SUCCESS;
}
int atsh_auth_verify(const char *user, const char *pass) {
    if (!user || !pass || !strlen(pass)) return ATSH_AUTH_FAIL;
    
    anti_bruteforce_wait();
    
    pam_handle_t *pamh = NULL;
    pam_data_t d = {.password = pass};
    struct pam_conv conv = {pam_conv_fn, &d};
    
    int r = pam_start("atsh", user, &conv, &pamh);
    if (r != PAM_SUCCESS) r = pam_start("login", user, &conv, &pamh);
    if (r != PAM_SUCCESS) return ATSH_AUTH_ERROR;
    
    r = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    pam_end(pamh, r);
    
    if (r == PAM_SUCCESS) { anti_bruteforce_success(); return ATSH_AUTH_OK; }
    anti_bruteforce_fail();
    return ATSH_AUTH_FAIL;
}
#elif defined(__ANDROID__)

int atsh_auth_verify(const char *user, const char *pass) {
    if (!user || !pass || !strlen(pass)) return ATSH_AUTH_FAIL;
    anti_bruteforce_wait();
    int ok = termux_auth(user, pass);
    if (ok) { anti_bruteforce_success(); return ATSH_AUTH_OK; }
    anti_bruteforce_fail();
    return ATSH_AUTH_FAIL;
}
#else

int atsh_auth_verify(const char *user, const char *pass) {
    if (!user||!pass) return ATSH_AUTH_ERROR;
    struct passwd *pw = getpwnam(user);
    if (!pw||!pw->pw_passwd||strlen(pw->pw_passwd)<13) return ATSH_AUTH_FAIL;
    char *h = crypt(pass, pw->pw_passwd);
    return (h&&!strcmp(h,pw->pw_passwd))?ATSH_AUTH_OK:ATSH_AUTH_FAIL;
}
#endif

int atsh_auth_init(void) { return 0; }
int atsh_auth_prompt(const char *user, char *pass, size_t len, atsh_password_cb cb) {
    (void)user; (void)cb;
    if (!pass||!len) return -1;
    printf("Password: "); fflush(stdout);
    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old; new.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new);
    if (!fgets(pass, (int)len, stdin)) { tcsetattr(STDIN_FILENO, TCSANOW, &old); return -1; }
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
    pass[strcspn(pass,"\r\n")]='\0';
    return (int)strlen(pass);
}
void atsh_auth_wipe_password(char *pass, size_t len) {
    if (pass&&len) explicit_bzero(pass, len);
}
