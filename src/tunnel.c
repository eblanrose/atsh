
#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int atsh_tunnel_init(TunnelContext *ctx, size_t max_tunnels) {
    if (!ctx || max_tunnels == 0) return -1;

    memset(ctx, 0, sizeof(TunnelContext));

    ctx->tunnels = calloc(max_tunnels, sizeof(TunnelState));
    if (!ctx->tunnels) return -1;

    ctx->num_tunnels = max_tunnels;

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        free(ctx->tunnels);
        return -1;
    }

    return 0;
}

int atsh_tunnel_add(TunnelContext *ctx, TunnelConfig *cfg) {
    if (!ctx || !cfg) return -1;

    for (size_t i = 0; i < ctx->num_tunnels; i++) {
        if (!ctx->tunnels[i].config.enabled) {
            memcpy(&ctx->tunnels[i].config, cfg, sizeof(TunnelConfig));
            ctx->tunnels[i].config.enabled = 1;
            ctx->tunnels[i].listen_fd = -1;
            return (int)i;
        }
    }

    return -1;
}

int atsh_tunnel_remove(TunnelContext *ctx, size_t index) {
    if (!ctx || index >= ctx->num_tunnels) return -1;

    TunnelState *t = &ctx->tunnels[index];

    if (t->listen_fd >= 0) {
        epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, t->listen_fd, NULL);
        close(t->listen_fd);
    }

    memset(t, 0, sizeof(TunnelState));
    return 0;
}

int atsh_tunnel_start_all(TunnelContext *ctx) {
    if (!ctx) return -1;

    for (size_t i = 0; i < ctx->num_tunnels; i++) {
        TunnelState *t = &ctx->tunnels[i];

        if (!t->config.enabled) continue;

        t->listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (t->listen_fd < 0) continue;

        int opt = 1;
        setsockopt(t->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(t->config.listen_port);

        if (bind(t->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(t->listen_fd);
            t->listen_fd = -1;
            continue;
        }

        if (listen(t->listen_fd, 10) < 0) {
            close(t->listen_fd);
            t->listen_fd = -1;
            continue;
        }

        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.u64 = i;
        epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, t->listen_fd, &ev);

        printf("[Tunnel %zu] Listening on :%d -> %s:%d\n",
               i, t->config.listen_port,
               t->config.remote_host, t->config.remote_port);
    }

    return 0;
}

int atsh_tunnel_poll(TunnelContext *ctx, int timeout_ms) {
    if (!ctx) return -1;

    struct epoll_event events[64];
    int nfds = epoll_wait(ctx->epoll_fd, events, 64, timeout_ms);

    for (int i = 0; i < nfds; i++) {
        size_t idx = (size_t)events[i].data.u64;
        if (idx >= ctx->num_tunnels) continue;

        TunnelState *t = &ctx->tunnels[idx];

        if (events[i].events & EPOLLIN) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);

            int client_fd = accept4(t->listen_fd,
                                   (struct sockaddr*)&client_addr, &addr_len,
                                   SOCK_NONBLOCK);
            if (client_fd < 0) continue;

            int target_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (target_fd < 0) {
                close(client_fd);
                continue;
            }

            struct sockaddr_in target_addr = {0};
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(t->config.remote_port);

            struct hostent *host = gethostbyname(t->config.remote_host);
            if (!host) {
                close(client_fd);
                close(target_fd);
                continue;
            }
            memcpy(&target_addr.sin_addr, host->h_addr, host->h_length);

            if (connect(target_fd, (struct sockaddr*)&target_addr,
                       sizeof(target_addr)) < 0 && errno != EINPROGRESS) {
                close(client_fd);
                close(target_fd);
                continue;
            }

            struct epoll_event ev = {0};
            ev.events = EPOLLIN;

            ev.data.u64 = (uint64_t)client_fd;
            epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

            ev.data.u64 = (uint64_t)target_fd;
            epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, target_fd, &ev);

            t->active_connections++;
        }
    }

    return nfds;
}

int atsh_tunnel_forward_data(int src_fd, int dst_fd) {
    char buf[65536];
    ssize_t n = read(src_fd, buf, sizeof(buf));
    if (n <= 0) return (int)n;

    ssize_t written = write(dst_fd, buf, (size_t)n);
    return (int)written;
}

void atsh_tunnel_cleanup(TunnelContext *ctx) {
    if (!ctx) return;

    for (size_t i = 0; i < ctx->num_tunnels; i++) {
        if (ctx->tunnels[i].listen_fd >= 0) {
            close(ctx->tunnels[i].listen_fd);
        }
    }

    if (ctx->epoll_fd >= 0) {
        close(ctx->epoll_fd);
    }

    free(ctx->tunnels);
    memset(ctx, 0, sizeof(TunnelContext));
}
