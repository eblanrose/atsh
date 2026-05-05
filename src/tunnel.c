
#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

int atsh_tunnel_init(TunnelContext *ctx, size_t max_tunnels) {
    if (!ctx || max_tunnels == 0) return -1;
    memset(ctx, 0, sizeof(TunnelContext));
    ctx->tunnels = calloc(max_tunnels, sizeof(TunnelState));
    if (!ctx->tunnels) return -1;
    ctx->num_tunnels = max_tunnels;
    signal(SIGCHLD, SIG_IGN);
    return 0;
}

int atsh_tunnel_add(TunnelContext *ctx, TunnelConfig *cfg) {
    if (!ctx || !cfg) return -1;
    for (size_t i = 0; i < ctx->num_tunnels; i++) {
        if (!ctx->tunnels[i].config.enabled) {
            memcpy(&ctx->tunnels[i].config, cfg, sizeof(TunnelConfig));
            ctx->tunnels[i].config.enabled = 1;
            return (int)i;
        }
    }
    return -1;
}

int atsh_tunnel_remove(TunnelContext *ctx, size_t index) {
    if (!ctx || index >= ctx->num_tunnels) return -1;
    TunnelState *t = &ctx->tunnels[index];
    if (t->listen_fd >= 0) close(t->listen_fd);
    if (t->epoll_fd >= 0) close(t->epoll_fd);
    memset(t, 0, sizeof(TunnelState));
    ctx->active_count--;
    return 0;
}


static void tcp_forward(int client_fd, const char *host, uint16_t port) {
    int target = socket(AF_INET, SOCK_STREAM, 0);
    if (target < 0) { close(client_fd); return; }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    struct hostent *h = gethostbyname(host);
    if (!h || connect(target, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(client_fd); close(target); return;
    }
    
    fd_set fds;
    char buf[65536];
    
    while (1) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(target, &fds);
        int max = (client_fd > target) ? client_fd : target;
        
        if (select(max+1, &fds, NULL, NULL, NULL) < 0) break;
        
        if (FD_ISSET(client_fd, &fds)) {
            ssize_t n = read(client_fd, buf, sizeof(buf));
            if (n <= 0) break;
            write(target, buf, (size_t)n);
        }
        if (FD_ISSET(target, &fds)) {
            ssize_t n = read(target, buf, sizeof(buf));
            if (n <= 0) break;
            write(client_fd, buf, (size_t)n);
        }
    }
    close(client_fd);
    close(target);
}


static void udp_forward(int client_fd, const char *host, uint16_t port) {
    
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { close(client_fd); return; }
    
    struct sockaddr_in target_addr = {0};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    
    struct hostent *h = gethostbyname(host);
    if (!h) { close(client_fd); close(udp_fd); return; }
    memcpy(&target_addr.sin_addr, h->h_addr, h->h_length);
    
    fd_set fds;
    char buf[65536];
    
    while (1) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(udp_fd, &fds);
        int max = (client_fd > udp_fd) ? client_fd : udp_fd;
        
        if (select(max+1, &fds, NULL, NULL, NULL) < 0) break;
        
        if (FD_ISSET(client_fd, &fds)) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(client_fd, buf, sizeof(buf), 0, 
                                (struct sockaddr*)&from, &flen);
            if (n <= 0) break;
            sendto(udp_fd, buf, (size_t)n, 0, 
                   (struct sockaddr*)&target_addr, sizeof(target_addr));
        }
        if (FD_ISSET(udp_fd, &fds)) {
            ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0, NULL, NULL);
            if (n <= 0) break;
            sendto(client_fd, buf, (size_t)n, 0, NULL, 0);
        }
    }
    close(client_fd);
    close(udp_fd);
}

int atsh_tunnel_start(TunnelContext *ctx, size_t index) {
    if (!ctx || index >= ctx->num_tunnels) return -1;
    TunnelState *t = &ctx->tunnels[index];
    if (!t->config.enabled) return -1;
    
    int type = (t->config.proto == TUNNEL_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    t->listen_fd = socket(AF_INET, type, 0);
    if (t->listen_fd < 0) return -1;
    
    int opt = 1;
    setsockopt(t->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(t->config.listen_port);
    
    if (bind(t->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(t->listen_fd); return -1;
    }
    
    if (t->config.proto == TUNNEL_TCP) listen(t->listen_fd, 10);
    
    t->epoll_fd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = t->listen_fd };
    epoll_ctl(t->epoll_fd, EPOLL_CTL_ADD, t->listen_fd, &ev);
    
    t->running = 1;
    ctx->active_count++;
    printf("[Tunnel %zu] %s :%d -> %s:%d\n", index,
           t->config.proto == TUNNEL_UDP ? "UDP" : "TCP",
           t->config.listen_port, t->config.remote_host, t->config.remote_port);
    return 0;
}

int atsh_tunnel_start_all(TunnelContext *ctx) {
    if (!ctx) return -1;
    for (size_t i = 0; i < ctx->num_tunnels; i++)
        if (ctx->tunnels[i].config.enabled)
            atsh_tunnel_start(ctx, i);
    return 0;
}

int atsh_tunnel_poll(TunnelContext *ctx, int timeout_ms) {
    if (!ctx) return -1;
    
    for (size_t i = 0; i < ctx->num_tunnels; i++) {
        TunnelState *t = &ctx->tunnels[i];
        if (!t->running || t->epoll_fd < 0) continue;
        
        struct epoll_event events[4];
        int n = epoll_wait(t->epoll_fd, events, 4, 0);
        
        for (int j = 0; j < n; j++) {
            if (events[j].data.fd == t->listen_fd && (events[j].events & EPOLLIN)) {
                if (t->config.proto == TUNNEL_TCP) {
                    int client = accept(t->listen_fd, NULL, NULL);
                    if (client >= 0) {
                        pid_t pid = fork();
                        if (pid == 0) {
                            close(t->listen_fd);
                            tcp_forward(client, t->config.remote_host, t->config.remote_port);
                            _exit(0);
                        }
                        close(client);
                    }
                } else {
                    pid_t pid = fork();
                    if (pid == 0) {
                        int fd = dup(t->listen_fd);
                        udp_forward(fd, t->config.remote_host, t->config.remote_port);
                        _exit(0);
                    }
                }
            }
        }
    }
    (void)timeout_ms;
    return 0;
}

void atsh_tunnel_cleanup(TunnelContext *ctx) {
    if (!ctx) return;
    for (size_t i = 0; i < ctx->num_tunnels; i++) {
        if (ctx->tunnels[i].listen_fd >= 0) close(ctx->tunnels[i].listen_fd);
        if (ctx->tunnels[i].epoll_fd >= 0) close(ctx->tunnels[i].epoll_fd);
    }
    free(ctx->tunnels);
    memset(ctx, 0, sizeof(TunnelContext));
}
