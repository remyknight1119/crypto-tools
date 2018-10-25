#ifndef __CT_SSL_H__
#define __CT_SSL_H__

#include <stdbool.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>

#include "tcp.h"
#include "record.h"
#include "cipher.h"

#define SSL_PAYLOAD_MAX_LEN     65535

typedef struct _ssl_buffer_t {
    uint8_t             bf_data[SSL_PAYLOAD_MAX_LEN];
    uint16_t            bf_offset;
    uint16_t            bf_need_len;
} ssl_buffer_t;

typedef struct _ssl_half_conn_t {
    EVP_CIPHER_CTX      *hc_enc_read_ctx;
    EVP_MD_CTX          *hc_handshake_dgst;
    EVP_MD_CTX          *hc_read_hash;
    unsigned char       *hc_key_block;
    bool                hc_change_cipher_spec;
} ssl_half_conn_t; 

typedef struct _ssl_conn_t {
    tcp_conn_t          sc_conn;
    ssl_half_conn_t     sc_client;
    ssl_half_conn_t     sc_server;
    ssl_half_conn_t     *sc_curr;
    int                 sc_version;
    uint8_t             sc_client_random[SSL3_RANDOM_SIZE];
    uint8_t             sc_server_random[SSL3_RANDOM_SIZE];
    uint8_t             sc_data[SSL_PAYLOAD_MAX_LEN];
    uint8_t             sc_handshake_msg[SSL_PAYLOAD_MAX_LEN];
    uint32_t            sc_handshake_msg_offset;
    bool                sc_renego;
    bool                sc_explicit_iv;
    ssl_buffer_t        sc_client_buffer;
    ssl_buffer_t        sc_server_buffer;
    uint16_t            sc_data_len;
    uint8_t             sc_master_key[SSL_MAX_MASTER_KEY_LENGTH];
    uint32_t            sc_master_key_length;
    int                 sc_ext_master_secret;
    int                 sc_tlsext_use_etm;
    ssl_cipher_t        *sc_cipher;
    int                 sc_key_block_length;
    const EVP_CIPHER    *sc_evp_cipher;
    int                 sc_mac_type;
    int                 sc_mac_secret_size;
    const EVP_MD        *sc_new_hash;
} ssl_conn_t;

extern RSA *rsa_private_key;

typedef int (*record_proc_f)(ssl_conn_t *conn, void *data,
            uint16_t len, int client);

extern void ssl_msg_proc(connection_t *conn, void *record,
        uint16_t len, int client);
extern ssl_cipher_t *ssl_get_cipher_by_id(uint32_t id);
extern int ssl_init(const char *file);

#endif
