#ifndef __CT_RECORD_H__
#define __CT_RECORD_H__

#include <netinet/in.h>

#define RANDOM_BYTE_LEN     28

struct _record_t {
    uint8_t         rd_type;
    uint16_t        rd_version;
    uint16_t        rd_len;
} __attribute__ ((__packed__));

typedef struct _record_t record_t;

typedef struct _handshake_t {
    uint8_t         hk_type;
    uint8_t         hk_len[3];
} handshake_t;

typedef struct _random_t {
    uint32_t        rm_unixt_time;
    uint8_t         rm_random_bytes[RANDOM_BYTE_LEN];
} random_t;

typedef struct _client_hello_t {
    uint16_t        ch_version;
    random_t        ch_random;
} client_hello_t;

struct _ssl_conn_t;

extern int ssl_handshake_proc(struct _ssl_conn_t *conn, void *data,
            uint16_t len);

#endif
