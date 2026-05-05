
#ifndef ATSH_TUNNEL_H
#define ATSH_TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

typedef enum {
    TUNNEL_TCP = 0,
    TUNNEL_UDP = 1,
} TunnelProto;

typedef struct {
    TunnelProto proto;
    uint16_t listen_port;
    char remote_host[256];
    uint16_t remote_port;
    int enabled;
} TunnelConfig;

typedef struct {
    TunnelConfig config;
    int listen_fd;
    int epoll_fd;
    int running;
} TunnelState;

typedef struct {
    TunnelState *tunnels;
    size_t num_tunnels;
    size_t active_count;
} TunnelContext;

int atsh_tunnel_init(TunnelContext *ctx, size_t max_tunnels);
int atsh_tunnel_add(TunnelContext *ctx, TunnelConfig *cfg);
int atsh_tunnel_remove(TunnelContext *ctx, size_t index);
int atsh_tunnel_start(TunnelContext *ctx, size_t index);
int atsh_tunnel_start_all(TunnelContext *ctx);
int atsh_tunnel_poll(TunnelContext *ctx, int timeout_ms);
void atsh_tunnel_cleanup(TunnelContext *ctx);

#endif
