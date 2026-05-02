
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
#include "crypto.h"
#define BUFFER_SIZE 65536
typedef struct {
    int pty_master;
    pid_t shell_pid;
} ShellSession;
static volatile sig_atomic_t g_running = 1;
void sig_handler(int sig) { (void)sig; g_running = 0; }
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
void handle_client(int fd) {
    ATSHCrypto crypto;
    memset(&crypto, 0, sizeof(crypto));
    

    if (atsh_handshake_server(&crypto, fd) != 0) {
        fprintf(stderr, "Handshake failed\n");
        close(fd);
        return;
    }
    

    uint8_t type;
    uint8_t *data;
    size_t len;
    
    if (atsh_recv_frame(&crypto, fd, &type, &data, &len) != 0 || type != ATSH_MSG_AUTH) {
        fprintf(stderr, "Expected auth\n");
        close(fd);
        return;
    }
    
    char *creds = strndup((char*)data, len);
    free(data);
    char *user = creds;
    char *pass = strchr(creds, '\n');
    if (!pass) { free(creds); close(fd); return; }
    *pass++ = '\0';
    
    printf("Login: %s\n", user);
    
    uint8_t resp[32];
    int ok = (atsh_auth_verify(user, pass) == ATSH_AUTH_OK);
    snprintf((char*)resp, sizeof(resp), ok ? "OK" : "FAILED");
    printf("Auth %s\n", ok ? "OK" : "FAIL");
    
    atsh_send_frame(&crypto, fd, ATSH_MSG_AUTH, resp, strlen((char*)resp));
    
    if (!ok) { free(creds); atsh_crypto_wipe(&crypto); close(fd); return; }
    

    ShellSession sh = {.pty_master = -1, .shell_pid = -1};
    sh.shell_pid = shell_spawn(user, &sh.pty_master);
    free(creds);
    
    if (sh.shell_pid < 0) { atsh_crypto_wipe(&crypto); close(fd); return; }
    
    char buf[BUFFER_SIZE];
    char esc[32];
    int esc_pos = 0, in_esc = 0;
    
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        if (sh.pty_master >= 0) FD_SET(sh.pty_master, &fds);
        int maxfd = (fd > sh.pty_master) ? fd : sh.pty_master;
        
        if (select(maxfd+1, &fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (FD_ISSET(fd, &fds)) {
            if (atsh_recv_frame(&crypto, fd, &type, &data, &len) != 0) break;
            
            if (type == ATSH_MSG_CLOSE) { free(data); break; }
            
            if (type == ATSH_MSG_DATA && sh.pty_master >= 0) {
                for (size_t i = 0; i < len; i++) {
                    char c = ((char*)data)[i];
                    if (!in_esc) {
                        if (c == '\033') { in_esc = 1; esc_pos = 0; esc[esc_pos++] = c; }
                        else write(sh.pty_master, &c, 1);
                    } else {
                        esc[esc_pos++] = c;
                        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='~') {
                            esc[esc_pos] = '\0';
                            int rows, cols;
                            if (sscanf(esc, "\033[8;%d;%dt", &rows, &cols) == 2 && rows>0 && cols>0) {
                                struct winsize ws = {rows, cols, 0, 0};
                                ioctl(sh.pty_master, TIOCSWINSZ, &ws);
                                kill(sh.shell_pid, SIGWINCH);
                            } else write(sh.pty_master, esc, esc_pos);
                            in_esc = 0; esc_pos = 0;
                        } else if (esc_pos >= 31) {
                            write(sh.pty_master, esc, esc_pos);
                            in_esc = 0; esc_pos = 0;
                        }
                    }
                }
                free(data);
            }
        }
        
        if (sh.pty_master >= 0 && FD_ISSET(sh.pty_master, &fds)) {
            ssize_t n = read(sh.pty_master, buf, sizeof(buf));
            if (n <= 0) break;
            atsh_send_frame(&crypto, fd, ATSH_MSG_DATA, (uint8_t*)buf, (size_t)n);
        }
    }
    
    if (sh.shell_pid > 0) { kill(sh.shell_pid, SIGTERM); waitpid(sh.shell_pid, NULL, 0); }
    if (sh.pty_master >= 0) close(sh.pty_master);
    atsh_crypto_wipe(&crypto);
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
    
    atsh_crypto_init();
    atsh_crypto_server_init("atsh.key", "atsh.crt");
    
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 10);
    
    printf("=== ATSH %s v%d.%d (RC2) ===\n", ATSH_CODENAME, ATSH_VERSION_MAJOR, ATSH_VERSION_MINOR);
    printf("Port: %d | Crypto: OpenSSL 1.1.1+ | Auth: %s\n", port,
#ifdef __ANDROID__
           "termux-auth"
#elif defined(__linux__)
           "PAM"
#else
           "crypt"
#endif
    );
    printf("===============================\n");
    
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
