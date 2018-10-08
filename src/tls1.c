#include <assert.h>
#include <openssl/ssl3.h>

#include  "ssl.h"
#include  "log.h"
#include  "record.h"
#include  "tls1.h"
#include  "cipher.h"


typedef int (*handshake_proc_f)(ssl_conn_t *ssl, PACKET *pkt, int client);
static int tls1_2_hello_request(ssl_conn_t *ssl, PACKET *pkt, int client);
static int tls1_2_client_hello(ssl_conn_t *ssl, PACKET *pkt, int client);
static int tls1_2_server_hello(ssl_conn_t *ssl, PACKET *pkt, int client);
static int tls1_2_new_session_ticket(ssl_conn_t *ssl, PACKET *pkt, int client);
static int tls1_2_client_key_exchange(ssl_conn_t *ssl,
            PACKET *pkt, int client);

typedef struct _ssl_key_t {
    uint32_t    ky_key;
    int         (*ky_process_key)(ssl_conn_t *ssl, PACKET *pkt);
} ssl_key_t;

typedef struct _ssl_extension_t {
    uint16_t    st_type;
    int         (*st_proc)(ssl_conn_t *ssl, uint8_t *data, uint16_t len);
} ssl_extension_t;


static handshake_proc_f tls1_2_handshake_handler[] = {
    tls1_2_hello_request, /* 0 */
    tls1_2_client_hello, /* 1 */
    tls1_2_server_hello, /* 2 */
    NULL, /* 3 */
    tls1_2_new_session_ticket, /* 4 */
    NULL, /* 5 */
    NULL, /* 6 */
    NULL, /* 7 */
    NULL, /* 8 */
    NULL, /* 9 */
    NULL, /* 10 */
    NULL, /* 11 */
    NULL, /* 12 */
    NULL, /* 13 */
    NULL, /* 14 */
    NULL, /* 15 */
    tls1_2_client_key_exchange, /* 16 */
    NULL, /* 17 */
    NULL, /* 18 */
    NULL, /* 19 */
    NULL, /* 20 */
    NULL, /* 21 */
    NULL, /* 22 */
};

#define TLS1_2_HANDSHAKE_HANDLER_NUM    CT_ARRAY_SIZE(tls1_2_handshake_handler)

static ssl_key_t key_proc[] = {
    {
        .ky_key = SSL_kRSA,
        .ky_process_key = tls_process_cke_rsa,
    },
};

#define TLS1_KEY_PROC_NUM       CT_ARRAY_SIZE(key_proc)

static int ssl_ext_extended_master_secret(ssl_conn_t *ssl,
        uint8_t *data, uint16_t len);
static int ssl_ext_use_etm(ssl_conn_t *ssl,
        uint8_t *data, uint16_t len);

static ssl_extension_t ext_proc[] = {
    {
        .st_type = TLSEXT_TYPE_extended_master_secret,
        .st_proc = ssl_ext_extended_master_secret,
    },
    {
        .st_type = TLSEXT_TYPE_encrypt_then_mac,
        .st_proc = ssl_ext_use_etm,
    },
};

#define SSL_EXT_PROC_NUM        CT_ARRAY_SIZE(ext_proc)

static int
tls1_2_hello_request(ssl_conn_t *ssl, PACKET *pkt, int client)
{
    ssl->sc_renego = 1;
    return 0;
}

static int
ssl_ext_extended_master_secret(ssl_conn_t *ssl,
        uint8_t *data, uint16_t len)
{
    ssl->sc_ext_master_secret = 1;
    CT_LOG("master\n");

    return 0;
}

static int
ssl_ext_use_etm(ssl_conn_t *ssl, uint8_t *data, uint16_t len)
{
    ssl->sc_tlsext_use_etm = 1;

    return 0;
}

static int
tls1_2_client_ext(ssl_conn_t *ssl, uint8_t *data, uint16_t len)
{
    extension_t     *ext = NULL;
    uint16_t        offset = 0;
    int             i = 0;

    CT_LOG("extlen=%d\n", len);

    while (offset < len) {
        ext = (void *)(data + offset);
        offset += sizeof(*ext) + ntohs(ext->et_length);
        for (i = 0; i < SSL_EXT_PROC_NUM; i++) {
            if (ext_proc[i].st_type == ntohs(ext->et_type)) {
                ext_proc[i].st_proc(ssl, (void *)(ext + 1),
                        ntohs(ext->et_length));
            }
        }
    }

    return 0;
}

static int
tls1_2_client_hello(ssl_conn_t *ssl, PACKET *pkt, int client)
{
    client_hello_t      *h = (void *)pkt->curr;
    uint8_t             *p = NULL;
    uint8_t             *comp_len = NULL;
    uint16_t            cipher_len = 0;
    uint16_t            ext_len = 0;

    assert(pkt->remaining >= sizeof(*h));
    memcpy(ssl->sc_client_random, &h->ch_random,
            sizeof(ssl->sc_client_random));
    CT_LOG("clientrandom:");
    CT_PRINT(h->ch_random.rm_random_bytes, (int)sizeof(ssl->sc_client_random));
    p = (void *)&h->ch_session_id[0];
    p += h->ch_session_id_len;
    cipher_len = ntohs(*((uint16_t *)p));
    p += sizeof(cipher_len) + cipher_len;
    comp_len = p;
    p += sizeof(*comp_len) + *comp_len;
    ext_len = ntohs(*((uint16_t *)p));

    return tls1_2_client_ext(ssl, p + sizeof(ext_len), ext_len);
}

static int
tls1_2_server_hello(ssl_conn_t *ssl, PACKET *pkt, int client)
{
    server_hello_t      *h = (void *)pkt->curr;
    uint8_t             *p = NULL;
    uint16_t            cipher = 0;

    assert(pkt->remaining >= sizeof(*h));
    memcpy(ssl->sc_server_random, &h->sh_random,
            sizeof(ssl->sc_server_random));
    CT_LOG("random = %x %x %x %x\n", ssl->sc_server_random[0],
            ssl->sc_server_random[1],ssl->sc_server_random[2],ssl->sc_server_random[3]);
    p = (void *)&h->sh_session_id[0];
    p += h->sh_session_id_len;
    cipher = ntohs(*((uint16_t *)p));

    ssl->sc_cipher = ssl_get_cipher_by_id(cipher);
    if (ssl->sc_cipher == NULL) {
        CT_LOG("Unsupport cipher %d\n", cipher);
        return -1;
    }

    CT_LOG("cipher = %x\n", cipher);
    return 0;
}

static int
tls1_2_client_key_exchange(ssl_conn_t *ssl, PACKET *pkt, int client)
{
    ssl_cipher_t    *cipher = ssl->sc_cipher;
    int             i = 0;
    
    if (cipher == NULL) {
        return -1;
    }

    for (i = 0; i < TLS1_KEY_PROC_NUM; i++) {
        if (key_proc[i].ky_key & cipher->sp_algorithm_mkey) {
            return key_proc[i].ky_process_key(ssl, pkt);
        }
    }

    return -1;
}

static int
tls1_2_new_session_ticket(ssl_conn_t *ssl, PACKET *pkt, int client)
{
    return 0;
}

static int
tls1_cbc_remove_padding(ssl_conn_t *ssl, unsigned char *out, uint16_t *olen,
        int bs, int mac_size, uint16_t *offset)
{
    unsigned char   *data = out;

    data += bs;
    *olen -= bs;
    *offset = bs;

    memmove(out, data, *olen);
    return 0;
}

int
tls1_enc(ssl_conn_t *ssl, unsigned char *out, uint16_t *olen,
        const unsigned char *in, uint32_t in_len)
{
    EVP_CIPHER_CTX      *ds = NULL;
    uint16_t            offset = 0;
    int                 bs = 0;

    ds = ssl->sc_curr->hc_enc_read_ctx;
    bs = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ds));
    //printf("-----------------------------ds=%p---------bs = %d\n",ds, bs);
    //CT_PRINT(in, in_len);
    EVP_Cipher(ds, out, in, in_len);
    *olen = in_len;
    tls1_cbc_remove_padding(ssl, out, olen, bs, ssl->sc_mac_secret_size,
            &offset);
    //CT_PRINT(out, *olen);
    //printf("--------------------------------------\n");

    return 0;
}

int
tls1_get_record(ssl_conn_t *ssl, const unsigned char *in, uint32_t len)
{
    uint32_t            clen = len;

    if (ssl->sc_tlsext_use_etm && ssl->sc_read_hash) {
        clen -= EVP_MD_CTX_size(ssl->sc_read_hash);
    }

    tls1_enc(ssl, ssl->sc_data, &ssl->sc_data_len, in, clen);

    return 0;
}

int
tls1_2_handshake_proc(ssl_conn_t *ssl, void *data,
            uint16_t len, int client)
{
    handshake_t         *h = NULL;
    bool                change_cipher_spec = 0;
    PACKET              pkt = {};
    handshake_proc_f    proc = NULL;
    uint16_t            offset = 0;
    uint32_t            mlen = 0;
    int                 finish = 0;

    h = data;
    while (offset < len) {
        change_cipher_spec = ssl->sc_curr->hc_change_cipher_spec;
        CT_LOG("server %d, ch = %d\n", !client, change_cipher_spec);
        if (change_cipher_spec == true) {
            tls1_get_record(ssl, (void *)h, len - offset);
            h = (void *)&ssl->sc_data[0];
            finish = 1;
        }
        mlen = ntohl(get_len_3byte(h->hk_len));
        CT_LOG("%s: type = %d, len = %d\n", client?"client":"server",h->hk_type, mlen);
        if (ssl->sc_renego) {
            CT_LOG("Renego handshake\n");
        }
        if (h->hk_type >= TLS1_2_HANDSHAKE_HANDLER_NUM) {
            CT_LOG("Unknown type = %d\n", h->hk_type);
            return -1;
        }

        proc = tls1_2_handshake_handler[h->hk_type];
        if (proc == NULL) {
            CT_LOG("Unsupported type = %d\n", h->hk_type);
            return -1;
        }

        pkt.curr = (void *)(h + 1);
        pkt.remaining = mlen;
        if (proc(ssl, &pkt, client) < 0) {
            return -1;
        }

        if (finish) {
            break;
        }
        offset += mlen + sizeof(*h);
        h = (void *)((char *)(h + 1) + mlen);
    }

    return 0;
}

int
tls1_2_application_data_proc(ssl_conn_t *ssl, void *data, uint16_t len,
            int lcient)
{
    return 0;
}

int
tls1_2_alert_proc(ssl_conn_t *ssl, void *data, uint16_t len, int lcient)
{
    return 0;
}

static int
tls1_2_init_enc_read(ssl_conn_t *ssl, EVP_CIPHER_CTX **dd, unsigned char *key,
        unsigned char *iv, int n)
{
    if ((*dd = EVP_CIPHER_CTX_new()) == NULL) {
        CT_LOG("New CTX failed!\n");
        return -1;
    }
    assert(n <= ssl->sc_key_block_length);
    if (!EVP_CipherInit_ex(*dd, ssl->sc_evp_cipher, NULL, key, iv, 0)) {
        CT_LOG("EVP_CipherInit_ex failed!\n");
        return -1;
    }

    return 0;
}

int
tls1_2_change_cipher_spec_proc(ssl_conn_t *ssl, void *data, uint16_t len,
            int client)
{
    EVP_MD_CTX          *mac_ctx = NULL;
    EVP_PKEY            *mac_key = NULL;
    ssl_half_conn_t     *conn = NULL; 
    uint8_t             *type = data;
    unsigned char       *ms = NULL;
    unsigned char       *mac_secret = NULL;
    unsigned char       *p = NULL;
    unsigned char       *key = NULL;
    unsigned char       *iv = NULL;
    int                 cl = 0;
    int                 i = 0;
    int                 j = 0;
    int                 k = 0;
    int                 n = 0;
    int                 ret = 0;

    conn = ssl->sc_curr;
    if (*type == TLS1_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC) {
        conn->hc_change_cipher_spec = true;
    }

    if (tls1_setup_key_block(ssl) != 0) {
        return -1;
    }

    p = ssl->sc_key_block;
    cl = EVP_CIPHER_key_length(ssl->sc_evp_cipher);
    j = cl;
    i = ssl->sc_mac_secret_size;
    k = EVP_CIPHER_iv_length(ssl->sc_evp_cipher);
    CT_LOG("change cipher type = %d, cl = %d, k = %d\n", *type, cl, k);
    if (client) {
        ms = &(p[0]);
        n = i + i;
        key = &(p[n]);
        n += j + j;
        iv = &(p[n]);
        n += k + k;
    } else {
        n = i;
        ms = &(p[n]);
        n += i + j;
        key = &(p[n]);
        n += j + k;
        iv = &(p[n]);
        n += k;
    }

    ret = tls1_2_init_enc_read(ssl, &conn->hc_enc_read_ctx, key, iv, n);
    if (ret < 0) {
        CT_LOG("Init enc failed!\n");
        return -1;
    }
    if (ssl->sc_read_hash != NULL) {
        return 0;
    }
    ssl->sc_read_hash = EVP_MD_CTX_new();
    if (ssl->sc_read_hash == NULL) {
        CT_LOG("New MD CTX failed!\n");
        return -1;
    }

    mac_ctx = ssl->sc_read_hash;
    mac_secret = ms;
    mac_key = EVP_PKEY_new_mac_key(ssl->sc_mac_type, NULL,
            mac_secret, ssl->sc_mac_secret_size);
    if (mac_key == NULL ||
            EVP_DigestSignInit(mac_ctx, NULL, ssl->sc_new_hash,
                NULL, mac_key) <= 0) {
        CT_LOG("Mac key failed!\n");
        return -1;
    }

    CT_LOG("MDSIZE = %d\n", EVP_MD_CTX_size(mac_ctx));

    return 0;
}

