
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "protocol.h"
#include "auth.h"

static volatile sig_atomic_t g_running = 1;
static struct termios orig_termios;
static int g_sockfd = -1;

void restore_terminal(void) { tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios); }
void sig_handler(int sig) { (void)sig; g_running = 0; }

void enable_raw_mode(void) {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(restore_terminal);
    struct termios raw = orig_termios;
    cfmakeraw(&raw);
    raw.c_lflag |= ISIG;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

int send_msg(int fd, uint8_t type, const uint8_t *data, size_t len) {
    ATSHHeader hdr = { .version = ATSH_VERSION_MAJOR, .type = type, .reserved = 0, .payload_size = (uint32_t)len };
    if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) return -1;
    if (data && len > 0) {
        size_t total = 0;
        while (total < len) {
            ssize_t n = write(fd, data + total, len - total);
            if (n <= 0) return -1;
            total += (size_t)n;
        }
    }
    return 0;
}

int recv_msg(int fd, uint8_t *type, uint8_t **data, size_t *len) {
    ATSHHeader hdr;
    size_t total = 0;
    while (total < sizeof(hdr)) {
        ssize_t n = read(fd, (uint8_t*)&hdr + total, sizeof(hdr) - total);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    *type = hdr.type;
    *len = hdr.payload_size;
    if (*len > 0) {
        *data = malloc(*len);
        if (!*data) return -1;
        total = 0;
        while (total < *len) {
            ssize_t n = read(fd, *data + total, *len - total);
            if (n <= 0) { free(*data); return -1; }
            total += (size_t)n;
        }
    } else {
        *data = NULL;
    }
    return 0;
}

void send_winsize(void) {
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0) return;
    char msg[32];
    int l = snprintf(msg, sizeof(msg), "\033[8;%d;%dt", ws.ws_row, ws.ws_col);
    if (l > 0) send_msg(g_sockfd, ATSH_MSG_WINSIZE, (uint8_t*)msg, (size_t)l);
}

void winch_handler(int sig) { (void)sig; send_winsize(); }

int main(int argc, char *argv[]) {
    char *host = NULL;
    uint16_t port = ATSH_DEFAULT_PORT;
    char *username = NULL, *password = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i+1 < argc) port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-u") && i+1 < argc) username = argv[++i];
        else if (!strcmp(argv[i], "-pw") && i+1 < argc) password = argv[++i];
        else if (!strcmp(argv[i], "-h")) {
            printf("ATSH %s Client v%d.%d\nUsage: %s <host> [-p port] [-u user] [-pw pass]\n",
                   ATSH_CODENAME, ATSH_VERSION_MAJOR, ATSH_VERSION_MINOR, argv[0]);
            return 0;
        } else if (!host) host = argv[i];
    }

    if (!host) { fprintf(stderr, "Usage: %s <host>\n", argv[0]); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    g_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *h = gethostbyname(host);
    if (!h) { perror("gethostbyname"); return 1; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, h->h_addr, h->h_length);

    printf("Connecting to %s:%d...\n", host, port);
    if (connect(g_sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }

    char *user = username;
    char *pass = password;

    if (!user) { printf("login: "); fflush(stdout); char buf[128]; fgets(buf,sizeof(buf),stdin); buf[strcspn(buf,"\r\n")]=0; user = strdup(buf); }
    if (!pass) { char buf[128]; atsh_auth_prompt(user, buf, sizeof(buf), NULL); pass = strdup(buf); atsh_auth_wipe_password(buf, sizeof(buf)); }

    char creds[256];
    snprintf(creds, sizeof(creds), "%s\n%s", user, pass);
    send_msg(g_sockfd, ATSH_MSG_AUTH, (uint8_t*)creds, strlen(creds));

    uint8_t type;
    uint8_t *data;
    size_t len;
    if (recv_msg(g_sockfd, &type, &data, &len) != 0 || strncmp((char*)data, "OK", 2)) {
        printf("Access denied\n");
        free(data);
        return 1;
    }
    free(data);
    printf("Authenticated\n");

    enable_raw_mode();
    signal(SIGWINCH, winch_handler);
    usleep(300000);
    send_winsize();

    char buf[65536];
    while (g_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(g_sockfd, &fds);

        if (select(g_sockfd+1, &fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) { send_winsize(); continue; }
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            send_msg(g_sockfd, ATSH_MSG_DATA, (uint8_t*)buf, (size_t)n);
        }

        if (FD_ISSET(g_sockfd, &fds)) {
            if (recv_msg(g_sockfd, &type, &data, &len) != 0) {
                printf("\nConnection closed\n"); break;
            }
            if (type == ATSH_MSG_DATA) write(STDOUT_FILENO, data, len);
            free(data);
        }
    }

    restore_terminal();
    close(g_sockfd);
    return 0;
}
