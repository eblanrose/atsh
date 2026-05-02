#ifndef ATSH_PROTOCOL_H
#define ATSH_PROTOCOL_H
#include <stdint.h>
#include <stddef.h>
#define ATSH_DEFAULT_PORT 2811
#define ATSH_VERSION_MAJOR 1
#define ATSH_VERSION_MINOR 0
#define ATSH_CODENAME "Bell"
typedef enum {
    ATSH_MSG_AUTH        = 0x01,
    ATSH_MSG_DATA        = 0x02,
    ATSH_MSG_WINSIZE     = 0x03,
    ATSH_MSG_CLOSE       = 0x04,
    ATSH_MSG_TUNNEL_CONN = 0x10,
    ATSH_MSG_TUNNEL_DATA = 0x11,
} ATSHMessageType;
typedef struct __attribute__((packed)) {
    uint8_t  version;
    uint8_t  type;
    uint16_t reserved;
    uint32_t payload_size;
} ATSHHeader;
#endif
