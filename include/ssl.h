#ifndef __CT_SSL_H__
#define __CT_SSL_H__

#include <stdbool.h>
#include <openssl/ossl_typ.h>

#include "tcp.h"
#include "record.h"
#include "cipher.h"

#define SSL_PAYLOAD_MAX_LEN     65535

typedef struct _ssl_buffer_t {
    uint8_t             bf_data[SSL_PAYLOAD_MAX_LEN];
    uint16_t            bf_offset;
    uint16_t            bf_need_len;
} ssl_buffer_t;

typedef struct _ssl_conn_t {
    tcp_conn_t          sc_conn;
    uint8_t             sc_client_random[RANDOM_BYTE_LEN];
    uint8_t             sc_server_random[RANDOM_BYTE_LEN];
    ssl_buffer_t        sc_client_buffer;
    ssl_buffer_t        sc_server_buffer;
    bool                sc_renego;
    ssl_cipher_t        *sc_cipher;
    pre_master_secret_t sc_pre_master;
    EVP_PKEY            *sc_private_key;
} ssl_conn_t;

extern RSA *rsa_private_key;

typedef int (*record_proc_f)(ssl_conn_t *conn, void *data,
            uint16_t len, int client);

extern void ssl_msg_proc(connection_t *conn, void *record,
        uint16_t len, int client);
extern ssl_cipher_t *ssl_get_cipher_by_id(uint32_t id);
extern int ssl_init(const char *file);

#endif
