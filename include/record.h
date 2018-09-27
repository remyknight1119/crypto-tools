#ifndef __CT_RECORD_H__
#define __CT_RECORD_H__

#include <string.h>
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

typedef struct _extension_t {
    uint16_t        et_type;
    uint16_t        et_length;
} extension_t;

struct _client_hello_t {
    uint16_t        ch_version;
    random_t        ch_random;
    uint8_t         ch_session_id_len;
    uint8_t         ch_session_id[0];
} __attribute__ ((__packed__));

typedef struct _client_hello_t client_hello_t;

struct _server_hello_t {
    uint16_t        sh_version;
    random_t        sh_random;
    uint8_t         sh_session_id_len;
    uint8_t         sh_session_id[0];
} __attribute__ ((__packed__));

typedef struct _server_hello_t server_hello_t;

static inline uint32_t get_len_3byte(uint8_t *len)
{
    union {
        uint32_t    len32;
        uint8_t     len8[4];
    } mlen;

    mlen.len8[0] = 0;
    memcpy(&mlen.len8[1], len, 3*sizeof(*len));

    return mlen.len32;
}


#endif
