#include "nap.h"
#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/wait.h>

typedef struct {
    struct NAPClient *cli;
    uint16_t server_port;
    char target_host[256];
    uint16_t target_port;
    int running;
    int control_fd;
    pthread_t thread;
} ReverseTunnel;

static ReverseTunnel *g_reverse_tunnel = NULL;
static pthread_mutex_t tunnel_mutex = PTHREAD_MUTEX_INITIALIZER;

static void set_tcp_nodelay(int fd) {
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static void tcp_forward_bidirectional(int fd1, int fd2) {
    set_tcp_nodelay(fd1);
    set_tcp_nodelay(fd2);
    
    fd_set fds;
    char buf[8192];
    
    while (1) {
        FD_ZERO(&fds);
        FD_SET(fd1, &fds);
        FD_SET(fd2, &fds);
        int maxfd = (fd1 > fd2) ? fd1 : fd2;
        struct timeval tv = {0, 10000};
        
        if (select(maxfd + 1, &fds, NULL, NULL, &tv) < 0) break;
        
        if (FD_ISSET(fd1, &fds)) {
            ssize_t n = read(fd1, buf, sizeof(buf));
            if (n <= 0) break;
            write(fd2, buf, n);
        }
        if (FD_ISSET(fd2, &fds)) {
            ssize_t n = read(fd2, buf, sizeof(buf));
            if (n <= 0) break;
            write(fd1, buf, n);
        }
    }
    close(fd1);
    close(fd2);
}

static void *reverse_tunnel_thread(void *arg) {
    ReverseTunnel *rt = (ReverseTunnel*)arg;
    int listen_fd = -1;
    
    printf("[Reverse] Tunnel active: server :%d -> client %s:%d\n",
           rt->server_port, rt->target_host, rt->target_port);
    
    while (rt->running) {
        if (listen_fd < 0) {
            listen_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (listen_fd < 0) {
                sleep(1);
                continue;
            }
            
            int opt = 1;
            setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(rt->server_port);
            
            if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(listen_fd);
                listen_fd = -1;
                sleep(1);
                continue;
            }
            
            if (listen(listen_fd, 5) < 0) {
                close(listen_fd);
                listen_fd = -1;
                sleep(1);
                continue;
            }
            
            set_tcp_nodelay(listen_fd);
            printf("[Reverse] Listening on :%d\n", rt->server_port);
        }
        
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        
        printf("[Reverse] Connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        int target_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (target_fd < 0) {
            close(client_fd);
            continue;
        }
        
        struct sockaddr_in target_addr = {0};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(rt->target_port);
        
        struct hostent *h = gethostbyname(rt->target_host);
        if (!h) {
            close(client_fd);
            close(target_fd);
            continue;
        }
        memcpy(&target_addr.sin_addr, h->h_addr, h->h_length);
        
        if (connect(target_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            close(client_fd);
            close(target_fd);
            continue;
        }
        
        set_tcp_nodelay(target_fd);
        
        pid_t pid = fork();
        if (pid == 0) {
            close(listen_fd);
            tcp_forward_bidirectional(client_fd, target_fd);
            _exit(0);
        } else if (pid > 0) {
            close(client_fd);
            close(target_fd);
        }
    }
    
    if (listen_fd >= 0) close(listen_fd);
    return NULL;
}

int atsh_tunnel_start_reverse(struct NAPClient *cli, uint16_t server_port,
                               const char *target_host, uint16_t target_port) {
    if (g_reverse_tunnel) return -1;
    
    ReverseTunnel *rt = calloc(1, sizeof(ReverseTunnel));
    if (!rt) return -1;
    
    rt->cli = cli;
    rt->server_port = server_port;
    strncpy(rt->target_host, target_host, 255);
    rt->target_host[255] = '\0';
    rt->target_port = target_port;
    rt->running = 1;
    rt->control_fd = -1;
    
    if (pthread_create(&rt->thread, NULL, reverse_tunnel_thread, rt) != 0) {
        free(rt);
        return -1;
    }
    
    g_reverse_tunnel = rt;
    return 0;
}

void atsh_tunnel_stop_all_reverse(void) {
    if (g_reverse_tunnel) {
        g_reverse_tunnel->running = 0;
        pthread_join(g_reverse_tunnel->thread, NULL);
        free(g_reverse_tunnel);
        g_reverse_tunnel = NULL;
    }
}
