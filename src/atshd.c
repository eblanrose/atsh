#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pty.h>
#include <pwd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <grp.h>
#include <time.h>

#include "protocol.h"
#include "auth.h"
#include "tunnel.h"

#define BUFFER_SIZE 65536

typedef struct {
    int pty_master;
    pid_t shell_pid;
    int authenticated;
} ShellSession;

static volatile sig_atomic_t g_running = 1;

void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

int shell_spawn(const char *username, int *pty_fd) {
    int master;
    struct winsize ws = {24, 80, 0, 0};
    pid_t pid = forkpty(&master, NULL, NULL, &ws);

    if (pid < 0) { perror("forkpty"); return -1; }

    if (pid == 0) {
        struct passwd *pw = getpwnam(username);
        if (!pw) _exit(1);

        int termux = (access("/data/data/com.termux/files/usr/bin/bash", F_OK) == 0);

        setenv("PATH", termux ?
            "/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/bin/applets:/system/bin:/system/xbin" :
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("TERM", "xterm-256color", 1);
        setenv("COLORTERM", "truecolor", 1);
        setenv("HOME", pw->pw_dir, 1);
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
        setenv("PWD", pw->pw_dir, 1);

        const char *shell = pw->pw_shell;
        if (!shell || access(shell, X_OK) != 0)
            shell = termux ? "/data/data/com.termux/files/usr/bin/bash" :
                    (access("/bin/bash", X_OK) == 0 ? "/bin/bash" : "/bin/sh");
        setenv("SHELL", shell, 1);

        chdir(pw->pw_dir);

        if (pw->pw_uid != getuid()) {
            initgroups(pw->pw_name, pw->pw_gid);
            setgid(pw->pw_gid);
            setuid(pw->pw_uid);
        }

        char arg0[256];
        const char *base = strrchr(shell, '/');
        snprintf(arg0, sizeof(arg0), "-%s", base ? base+1 : shell);

        execl(shell, arg0, "-l", NULL);
        _exit(1);
    }

    *pty_fd = master;
    return pid;
}

int send_msg(int fd, uint8_t type, const uint8_t *data, size_t len) {
    ATSHHeader hdr = {
        .version = ATSH_VERSION_MAJOR,
        .type = type,
        .reserved = 0,
        .payload_size = (uint32_t)len
    };

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

void handle_client(int fd) {
    ShellSession shell = {.pty_master = -1, .shell_pid = -1, .authenticated = 0};
    uint8_t type;
    uint8_t *data;
    size_t len;

    if (recv_msg(fd, &type, &data, &len) != 0 || type != ATSH_MSG_AUTH) {
        fprintf(stderr, "Expected auth message\n");
        close(fd);
        return;
    }

    char *creds = strndup((char*)data, len);
    free(data);

    char *username = creds;
    char *password = strchr(creds, '\n');
    if (!password) {
        fprintf(stderr, "Invalid auth format\n");
        free(creds);
        close(fd);
        return;
    }
    *password++ = '\0';

    printf("Login: %s\n", username);

    uint8_t response[32];
    int auth_ok = (atsh_auth_verify(username, password) == ATSH_AUTH_OK);

    if (auth_ok) {
        snprintf((char*)response, sizeof(response), "OK");
        printf("Auth OK\n");
    } else {
        snprintf((char*)response, sizeof(response), "FAILED");
        printf("Auth FAIL\n");
    }

    send_msg(fd, ATSH_MSG_AUTH, response, strlen((char*)response));

    if (!auth_ok) {
        free(creds);
        close(fd);
        return;
    }

    shell.shell_pid = shell_spawn(username, &shell.pty_master);
    shell.authenticated = 1;
    free(creds);

    if (shell.shell_pid < 0) {
        close(fd);
        return;
    }

    char buf[BUFFER_SIZE];
    char esc_buf[32];
    int esc_pos = 0;
    int in_esc = 0;

    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        if (shell.pty_master >= 0) FD_SET(shell.pty_master, &fds);

        int maxfd = (fd > shell.pty_master) ? fd : shell.pty_master;

        if (select(maxfd+1, &fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(fd, &fds)) {
            if (recv_msg(fd, &type, &data, &len) != 0) break;

            if (type == ATSH_MSG_CLOSE) {
                free(data);
                break;
            }

            if (type == ATSH_MSG_DATA && shell.pty_master >= 0) {
                for (size_t i = 0; i < len; i++) {
                    char c = ((char*)data)[i];

                    if (!in_esc) {
                        if (c == '\033') {
                            in_esc = 1;
                            esc_pos = 0;
                            esc_buf[esc_pos++] = c;
                        } else {
                            write(shell.pty_master, &c, 1);
                        }
                    } else {
                        esc_buf[esc_pos++] = c;

                        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '~') {
                            esc_buf[esc_pos] = '\0';

                            int rows, cols;
                            if (sscanf(esc_buf, "\033[8;%d;%dt", &rows, &cols) == 2) {
                                if (rows > 0 && cols > 0 && rows < 1000 && cols < 1000) {
                                    struct winsize ws = {rows, cols, 0, 0};
                                    ioctl(shell.pty_master, TIOCSWINSZ, &ws);
                                    kill(shell.shell_pid, SIGWINCH);
                                }
                            } else {
                                write(shell.pty_master, esc_buf, esc_pos);
                            }

                            in_esc = 0;
                            esc_pos = 0;
                        } else if (esc_pos >= 31) {
                            write(shell.pty_master, esc_buf, esc_pos);
                            in_esc = 0;
                            esc_pos = 0;
                        }
                    }
                }
                free(data);
            }
        }

        if (shell.pty_master >= 0 && FD_ISSET(shell.pty_master, &fds)) {
            ssize_t n = read(shell.pty_master, buf, sizeof(buf));
            if (n <= 0) break;
            send_msg(fd, ATSH_MSG_DATA, (uint8_t*)buf, (size_t)n);
        }
    }

    if (shell.shell_pid > 0) {
        kill(shell.shell_pid, SIGTERM);
        waitpid(shell.shell_pid, NULL, 0);
    }
    if (shell.pty_master >= 0) close(shell.pty_master);
    close(fd);
    printf("Session closed\n");
}

int main(int argc, char *argv[]) {
    uint16_t port = ATSH_DEFAULT_PORT;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-p") && i+1 < argc)
            port = (uint16_t)atoi(argv[++i]);

    signal(SIGCHLD, SIG_DFL);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 10);

    printf("=== ATSH %s v%d.%d ===\n", ATSH_CODENAME, ATSH_VERSION_MAJOR, ATSH_VERSION_MINOR);
    printf("Port: %d\n", port);
    printf("========================\n");

    while (g_running) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int client = accept(srv, (struct sockaddr*)&cli, &cli_len);
        if (client < 0) continue;

        printf("Connection from %s:%d\n", inet_ntoa(cli.sin_addr), ntohs(cli.sin_port));

        pid_t pid = fork();
        if (pid == 0) {
            close(srv);
            handle_client(client);
            exit(0);
        }
        close(client);
    }

    close(srv);
    return 0;
}
