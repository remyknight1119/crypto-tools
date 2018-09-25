#ifndef __CT_CIPHER_H__
#define __CT_CIPHER_H__

#include "packet.h"

typedef struct _ssl_cipher_t {
    uint32_t    sp_id;
    uint32_t    sp_algorithm_mkey;
    uint32_t    sp_algorithm_enc;
    uint32_t    sp_algorithm_mac;
} ssl_cipher_t;

typedef struct _pre_master_secret_t {
    uint16_t    pm_len;
    uint8_t     pm_pre_master[512];
} pre_master_secret_t;

struct _ssl_conn_t;

extern int tls_process_cke_rsa(struct _ssl_conn_t *ssl, PACKET *pkt);

#endif
