#ifndef ATSH_TUNNEL_H
#define ATSH_TUNNEL_H

#include <stdint.h>
#include <netinet/in.h>

typedef enum {
    TUNNEL_LOCAL  = 0,
    TUNNEL_REMOTE = 1,
    TUNNEL_DYNAMIC = 2,
} TunnelType;

typedef struct {
    TunnelType type;
    uint16_t listen_port;
    char remote_host[256];
    uint16_t remote_port;
    int enabled;
} TunnelConfig;

typedef struct {
    TunnelConfig config;
    int listen_fd;
    int active_connections;
    uint64_t bytes_forwarded;
} TunnelState;

typedef struct {
    TunnelState *tunnels;
    size_t num_tunnels;
    int epoll_fd;
} TunnelContext;

int atsh_tunnel_init(TunnelContext *ctx, size_t max_tunnels);
int atsh_tunnel_add(TunnelContext *ctx, TunnelConfig *cfg);
int atsh_tunnel_remove(TunnelContext *ctx, size_t index);
int atsh_tunnel_start_all(TunnelContext *ctx);
int atsh_tunnel_poll(TunnelContext *ctx, int timeout_ms);
int atsh_tunnel_forward_data(int src_fd, int dst_fd);
void atsh_tunnel_cleanup(TunnelContext *ctx);

#endif // ATSH_TUNNEL_H
