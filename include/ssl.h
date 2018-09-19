#ifndef __CT_SSL_H__
#define __CT_SSL_H__

#include "tcp.h"
#include "record.h"

#define SSL_PAYLOAD_MAX_LEN     65535

typedef struct _ssl_conn_t {
    tcp_conn_t          sc_conn;
    uint8_t             sc_client_random[RANDOM_BYTE_LEN];
    uint8_t             sc_server_random[RANDOM_BYTE_LEN];
    uint8_t             sc_buf[SSL_PAYLOAD_MAX_LEN];
} ssl_conn_t;

extern void ssl_msg_proc(connection_t *conn, void *record, uint16_t len);

#endif
