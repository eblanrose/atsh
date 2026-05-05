
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "nap.h"
#include "protocol.h"
#include "auth.h"
#include "crypto.h"

static volatile sig_atomic_t g_running = 1;
static struct termios orig_termios;
static NAPClient g_cli;
static ATSHCrypto g_crypto;
static int g_crypto_on = 0;
static char *g_password = NULL;

void restore_terminal(void) { tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios); }
void sig_handler(int sig) { (void)sig; g_running = 0; }

void enable_raw_mode(void) {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(restore_terminal);
    struct termios raw = orig_termios;
    cfmakeraw(&raw); raw.c_lflag |= ISIG;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

void send_winsize(void) {
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0) return;
    char msg[32];
    int l = snprintf(msg, sizeof(msg), "\033[8;%d;%dt", ws.ws_row, ws.ws_col);
    if (l > 0) {
        if (g_crypto_on) {
            uint8_t *ct; size_t ct_len;
            atsh_encrypt_frame(&g_crypto, 0, (uint8_t*)msg, l, &ct, &ct_len);
            nap_client_send_data(&g_cli, ct, ct_len);
            free(ct);
        } else nap_client_send_data(&g_cli, (uint8_t*)msg, l);
    }
}

void winch_handler(int sig) { (void)sig; send_winsize(); }

int main(int argc, char *argv[]) {
    char *host = NULL;
    uint16_t port = ATSH_DEFAULT_PORT;
    char *user = NULL, *pass = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i+1 < argc) port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-u") && i+1 < argc) user = argv[++i];
        else if (!strcmp(argv[i], "-pw") && i+1 < argc) pass = argv[++i];
        else if (!strcmp(argv[i], "-h")) { printf("ATSH Bell RC3\n"); return 0; }
        else if (!host) host = argv[i];
    }
    if (!host) { fprintf(stderr, "Usage: %s <host>\n", argv[0]); return 1; }
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    if (nap_client_init(&g_cli) != 0) return 1;
    printf("Connecting to %s:%d...\n", host, port);
    if (nap_client_connect(&g_cli, host, port) != 0) { fprintf(stderr,"Connection failed\n"); return 1; }

    if (!user) { printf("login: "); fflush(stdout); char b[128]; fgets(b,sizeof(b),stdin); b[strcspn(b,"\r\n")]=0; user = strdup(b); }
    if (!pass) { char b[128]; atsh_auth_prompt(user, b, sizeof(b), NULL); pass = strdup(b); atsh_auth_wipe_password(b,sizeof(b)); }
    g_password = pass;

    
    if (nap_client_auth(&g_cli, user, pass) != 0) { printf("Access denied\n"); return 1; }
    
    
    atsh_crypto_client_init(&g_crypto, g_cli.session_id, pass);
    g_crypto_on = 1;
    
    printf("Authenticated\n");
    enable_raw_mode();
    signal(SIGWINCH, winch_handler);
    usleep(300000);
    send_winsize();

    char buf[65536];
    while (g_running && g_cli.state == NAP_SESSION_ACTIVE) {
        fd_set fds;
        FD_ZERO(&fds); FD_SET(STDIN_FILENO, &fds);
        if (g_cli.fd >= 0) FD_SET(g_cli.fd, &fds);
        int maxfd = (STDIN_FILENO > g_cli.fd) ? STDIN_FILENO : g_cli.fd;
        struct timeval tv = {0, 100000};
        if (select(maxfd+1, &fds, NULL, NULL, &tv) < 0) {
            if (errno == EINTR) { send_winsize(); continue; }
            break;
        }
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            if (g_crypto_on) {
                uint8_t *ct; size_t ct_len;
                atsh_encrypt_frame(&g_crypto, 0, (uint8_t*)buf, n, &ct, &ct_len);
                nap_client_send_data(&g_cli, ct, ct_len); free(ct);
            } else nap_client_send_data(&g_cli, (uint8_t*)buf, n);
        }
        if (g_cli.fd >= 0 && FD_ISSET(g_cli.fd, &fds)) {
            uint8_t t; uint8_t *d; size_t l;
            if (nap_client_recv(&g_cli, &t, &d, &l) == 0) {
                if (g_crypto_on) {
                    uint8_t *pt; size_t ptl;
                    atsh_decrypt_frame(&g_crypto, d, l, &pt, &ptl);
                    if (pt && ptl) write(STDOUT_FILENO, pt, ptl);
                    free(pt);
                } else if (l > 0) write(STDOUT_FILENO, d, l);
                free(d);
            }
        }
    }
    restore_terminal();
    atsh_crypto_wipe(&g_crypto);
    nap_client_close(&g_cli);
    return 0;
}
