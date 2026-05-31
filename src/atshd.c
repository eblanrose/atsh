#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <grp.h>
#include <time.h>

#ifdef __linux__
#include <pty.h>
#elif defined(__FreeBSD__)
#include <libutil.h>
#endif

#include "nap.h"
#include "protocol.h"
#include "auth.h"
#include "crypto.h"
#include "tunnel.h"

#define BUFFER_SIZE 8192

typedef struct {
    int pty_master;
    pid_t shell_pid;
    ATSHCrypto crypto;
    int crypto_ready;
    int session_closing;
} ShellSession;

static volatile sig_atomic_t g_running = 1;
static NAPServer g_nap;
static TunnelContext g_tunnels;

static void sig_handler(int sig) { (void)sig; g_running = 0; }

static int is_shell_alive(pid_t pid) {
    if (pid <= 0) return 0;
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == pid) {
        return 0;
    }
    if (kill(pid, 0) == -1 && errno == ESRCH) {
        return 0;
    }
    return 1;
}

static int shell_spawn(const char *username, int *pty_fd) {
    int master;
    struct winsize ws = {24, 80, 0, 0};
    pid_t pid = forkpty(&master, NULL, NULL, &ws);
    if (pid < 0) return -1;
    if (pid == 0) {
        struct passwd *pw = getpwnam(username);
        if (!pw) _exit(1);
        int termux = (access("/data/data/com.termux/files/usr/bin/bash", F_OK) == 0);
        setenv("PATH", termux ?
            "/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/bin/applets:/system/bin:/system/xbin" :
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("TERM", "xterm-256color", 1);
        setenv("HOME", pw->pw_dir, 1);
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
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
    fcntl(master, F_SETFL, fcntl(master, F_GETFL, 0) | O_NONBLOCK);
    return pid;
}

static void kill_session(ShellSession *s) {
    if (!s) return;
    if (s->shell_pid > 0 && !s->session_closing) {
        s->session_closing = 1;
        kill(s->shell_pid, SIGTERM);
        usleep(100000);
        kill(s->shell_pid, SIGKILL);
        waitpid(s->shell_pid, NULL, WNOHANG);
    }
    atsh_crypto_wipe(&s->crypto);
    if (s->pty_master >= 0) close(s->pty_master);
    free(s);
}

static void on_nap_connect(uint32_t sid, struct sockaddr_in *addr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    printf("[%u] Connected from %s:%d\n", sid, ip, ntohs(addr->sin_port));
}

static int on_nap_auth(uint32_t sid, const char *username, const char *password) {
    printf("[%u] Auth: %s\n", sid, username);
    int ok = (atsh_auth_verify(username, password) == ATSH_AUTH_OK);
    printf("[%u] Auth %s\n", sid, ok ? "OK" : "FAIL");
    if (ok) {
        for (size_t i = 0; i < g_nap.max_sessions; i++) {
            if (g_nap.sessions[i].session_id == sid) {
                ShellSession *shell = calloc(1, sizeof(ShellSession));
                if (!shell) {
                    printf("[%u] Memory allocation failed\n", sid);
                    return -1;
                }
                shell->shell_pid = shell_spawn(username, &shell->pty_master);
                if (shell->shell_pid < 0) {
                    free(shell);
                    return -1;
                }
                atsh_crypto_server_init_session(&shell->crypto, sid, password);
                shell->crypto_ready = 1;
                shell->session_closing = 0;
                g_nap.sessions[i].user_data = shell;
                break;
            }
        }
    }
    return ok ? 0 : -1;
}

static void on_nap_data(uint32_t sid, uint8_t channel, const uint8_t *data, size_t len) {
    (void)channel;
    ShellSession *shell = NULL;
    for (size_t i = 0; i < g_nap.max_sessions; i++) {
        if (g_nap.sessions[i].session_id == sid &&
            g_nap.sessions[i].state == NAP_SESSION_ACTIVE) {
            shell = (ShellSession*)g_nap.sessions[i].user_data;
            break;
        }
    }
    if (!shell || shell->pty_master < 0 || shell->session_closing) return;

    uint8_t *pt; size_t pt_len;
    if (shell->crypto_ready) {
        atsh_decrypt_frame(&shell->crypto, data, len, &pt, &pt_len);
    } else {
        pt = malloc(len);
        if (!pt) return;
        memcpy(pt, data, len);
        pt_len = len;
    }
    
    for (size_t i = 0; i < pt_len; i++) {
        char c = ((char*)pt)[i];
        if (c == '\033') {
            char esc[32]; int ep = 1; esc[0] = '\033';
            while (++i < pt_len && ep < 31) {
                esc[ep++] = ((char*)pt)[i];
                char x = ((char*)pt)[i];
                if ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || x == '~') {
                    esc[ep] = '\0';
                    int rows, cols;
                    if (sscanf(esc, "\033[8;%d;%dt", &rows, &cols) == 2 && rows > 0) {
                        struct winsize ws = {rows, cols, 0, 0};
                        ioctl(shell->pty_master, TIOCSWINSZ, &ws);
                        kill(shell->shell_pid, SIGWINCH);
                    } else write(shell->pty_master, esc, ep);
                    break;
                }
            }
        } else write(shell->pty_master, &c, 1);
    }
    free(pt);
}

static void on_nap_disconnect(uint32_t sid) {
    printf("[%u] Disconnected\n", sid);
    for (size_t i = 0; i < g_nap.max_sessions; i++) {
        if (g_nap.sessions[i].session_id == sid) {
            kill_session((ShellSession*)g_nap.sessions[i].user_data);
            g_nap.sessions[i].user_data = NULL;
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    uint16_t port = ATSH_DEFAULT_PORT;
    TunnelConfig tunnels[16];
    size_t num_tunnels = 0;
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i+1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "-t") && i+3 < argc && num_tunnels < 16) {
            tunnels[num_tunnels].proto = TUNNEL_TCP;
            tunnels[num_tunnels].listen_port = (uint16_t)atoi(argv[i+1]);
            strncpy(tunnels[num_tunnels].remote_host, argv[i+2], 255);
            tunnels[num_tunnels].remote_port = (uint16_t)atoi(argv[i+3]);
            tunnels[num_tunnels].remote_host[255] = '\0';
            tunnels[num_tunnels].enabled = 1;
            num_tunnels++;
            i += 3;
        }
        else if (!strcmp(argv[i], "-u") && i+3 < argc && num_tunnels < 16) {
            tunnels[num_tunnels].proto = TUNNEL_UDP;
            tunnels[num_tunnels].listen_port = (uint16_t)atoi(argv[i+1]);
            strncpy(tunnels[num_tunnels].remote_host, argv[i+2], 255);
            tunnels[num_tunnels].remote_port = (uint16_t)atoi(argv[i+3]);
            tunnels[num_tunnels].remote_host[255] = '\0';
            tunnels[num_tunnels].enabled = 1;
            num_tunnels++;
            i += 3;
        }
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGCHLD, SIG_IGN);
    
    atsh_tunnel_init(&g_tunnels, 16);
    for (size_t i = 0; i < num_tunnels; i++) {
        atsh_tunnel_add(&g_tunnels, &tunnels[i]);
    }
    atsh_tunnel_start_all(&g_tunnels);
    
    memset(&g_nap, 0, sizeof(g_nap));
    g_nap.on_connect = on_nap_connect;
    g_nap.on_auth = on_nap_auth;
    g_nap.on_data = on_nap_data;
    g_nap.on_disconnect = on_nap_disconnect;
    
    if (nap_server_init(&g_nap, port, 16) < 0) return 1;
    
    printf("=== ATSH Bell :%d ===\n", port);
    
    while (g_running) {
        nap_server_poll(&g_nap, 100);
        atsh_tunnel_poll(&g_tunnels, 0);
        
        for (size_t i = 0; i < g_nap.max_sessions; i++) {
            NAPSession *sess = &g_nap.sessions[i];
            if (sess->state != NAP_SESSION_ACTIVE || !sess->user_data) continue;
            ShellSession *shell = (ShellSession*)sess->user_data;
            if (shell->pty_master < 0) continue;
            
            if (!is_shell_alive(shell->shell_pid) && !shell->session_closing) {
                printf("[%u] Shell process died, closing session\n", sess->session_id);
                shell->session_closing = 1;
                nap_server_send(&g_nap, sess->session_id, NAP_MSG_CLOSE, NULL, 0);
                nap_server_close_session(&g_nap, sess->session_id);
                continue;
            }
            
            char buf[BUFFER_SIZE];
            ssize_t n = read(shell->pty_master, buf, sizeof(buf));
            if (n > 0) {
                if (shell->crypto_ready) {
                    uint8_t *ct; size_t ct_len;
                    atsh_encrypt_frame(&shell->crypto, 0, (uint8_t*)buf, n, &ct, &ct_len);
                    nap_server_send(&g_nap, sess->session_id, NAP_MSG_DATA, ct, ct_len);
                    free(ct);
                } else {
                    nap_server_send(&g_nap, sess->session_id, NAP_MSG_DATA, (uint8_t*)buf, n);
                }
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            } else if (n == 0 && !shell->session_closing) {
                printf("[%u] EOF on pty, closing session\n", sess->session_id);
                shell->session_closing = 1;
                nap_server_send(&g_nap, sess->session_id, NAP_MSG_CLOSE, NULL, 0);
                nap_server_close_session(&g_nap, sess->session_id);
            }
        }
    }
    
    atsh_tunnel_cleanup(&g_tunnels);
    nap_server_cleanup(&g_nap);
    return 0;
}
