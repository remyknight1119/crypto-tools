#ifndef __CT_TCP_H__
#define __CT_TCP_H__

#include "connect.h"

enum {
    TCP_STATE_SYN,
    TCP_STATE_SYN_ACK,
    TCP_STATE_EST,
    TCP_STATE_CLIENT_FIN,
    TCP_STATE_SERVER_FIN,
};

typedef struct _tcp_conn_t {
    connection_t            tp_conn;
} tcp_conn_t;

extern void tcp_v4_handler(uint32_t daddr, uint32_t saddr,
            void *proto_header, uint16_t len);
extern tcp_conn_t *tcp_conn_find(connection_key_t key, int *client);
extern tcp_conn_t *tcp_conn_alloc(size_t size);
extern void tcp_conn_free(tcp_conn_t *conn);

#endif
