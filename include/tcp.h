#ifndef __CT_TCP_H__
#define __CT_TCP_H__

#include "connect.h"

typedef struct _tcp_conn_t {
    connection_t        tp_conn;
} tcp_conn_t;

extern void tcp_v4_handler(uint32_t daddr, uint32_t saddr,
            void *proto_header);
extern tcp_conn_t *tcp_conn_find(connection_key_t key);
extern tcp_conn_t *tcp_conn_alloc(void);
extern void tcp_conn_free(tcp_conn_t *conn);

#endif
