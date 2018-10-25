#include <assert.h>
#include <openssl/ssl3.h>
#include <openssl/evp.h>

#include  "ssl.h"
#include  "log.h"
#include  "record.h"
#include  "tls1.h"
#include  "cipher.h"
#include  "comm.h"


typedef int (*handshake_proc_f)(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_hello_request(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_client_hello(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_server_hello(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_server_certificate(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_certificate_request(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_server_done(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_certificate_verify(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_new_session_ticket(ssl_conn_t *ssl, PACKET *pkt);
static int tls1_2_client_key_exchange(ssl_conn_t *ssl,
            PACKET *pkt);
static int tls1_2_finished(ssl_conn_t *ssl, PACKET *pkt);

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
    tls1_2_server_certificate, /* 11 */
    NULL, /* 12 */
    tls1_2_certificate_request, /* 13 */
    tls1_2_server_done, /* 14 */
    tls1_2_certificate_verify, /* 15 */
    tls1_2_client_key_exchange, /* 16 */
    NULL, /* 17 */
    NULL, /* 18 */
    NULL, /* 19 */
    tls1_2_finished, /* 20 */
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
tls1_2_hello_request(ssl_conn_t *ssl, PACKET *pkt)
{
    CT_LOG("Renego start\n");
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
tls1_2_client_hello(ssl_conn_t *ssl, PACKET *pkt)
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
tls1_2_server_hello(ssl_conn_t *ssl, PACKET *pkt)
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
tls1_2_certificate_request(ssl_conn_t *ssl, PACKET *pkt)
{
    return 0;
}

static int
tls1_2_server_certificate(ssl_conn_t *ssl, PACKET *pkt)
{
    return 0;
}

static int
tls1_2_server_done(ssl_conn_t *ssl, PACKET *pkt)
{
    return 0;
}

static int
tls1_2_certificate_verify(ssl_conn_t *ssl, PACKET *pkt)
{
    return 0;
}

static int
tls1_2_client_key_exchange(ssl_conn_t *ssl, PACKET *pkt)
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
tls1_2_new_session_ticket(ssl_conn_t *ssl, PACKET *pkt)
{
    return 0;
}

static int
tls1_2_finished(ssl_conn_t *ssl, PACKET *pkt)
{
    ssl->sc_renego = 0;
    ssl->sc_handshake_msg_offset = 0;
    //ssl->sc_curr->hc_change_cipher_spec = false;
    return 0;
}

static int
tls1_cbc_remove_padding(ssl_conn_t *ssl, unsigned char *out, uint16_t *olen,
        int bs, int mac_size)
{
    EVP_CIPHER_CTX      *ds = NULL;
    unsigned char       *data = out;
    unsigned char       padding_len = 0;

    padding_len = data[*olen - 1];
    if (ssl->sc_explicit_iv) {
        data += bs;
        *olen -= bs;
    }
    CT_LOG("Padding len = %d, data len = %d, bs = %d\n",
            padding_len, *olen, bs);
    if (padding_len >= *olen) {
        CT_LOG("Padding len error\n");
        return -1;
    }

    ds = ssl->sc_curr->hc_enc_read_ctx;
    if (1 || EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(ds)) &
            EVP_CIPH_FLAG_AEAD_CIPHER) {
        CT_LOG("AEADDDDDCCCCCCCCCCCCCCCCCCCCCCCCCCC\n");
        *olen -= (padding_len + 1);
    }

    CT_LOG("olen = %d\n", *olen);
    memmove(out, data, *olen);
    return 0;
}

int
tls1_enc(ssl_conn_t *ssl, int type, unsigned char *out, uint16_t *olen,
        const unsigned char *in, uint32_t in_len)
{
    EVP_CIPHER_CTX      *ds = NULL;
    unsigned char       buf[EVP_AEAD_TLS1_AAD_LEN] = {};
    int                 bs = 0;
    int                 pad = 0;
    int                 ret = 0;

    ds = ssl->sc_curr->hc_enc_read_ctx;
    bs = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ds));
    if (EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(ds))
            & EVP_CIPH_FLAG_AEAD_CIPHER) {
        buf[8] = type;
        buf[9] = (unsigned char)(ssl->sc_version >> 8);
        buf[10] = (unsigned char)(ssl->sc_version);
        buf[11] = in_len >> 8;
        buf[12] = in_len & 0xff;

        CT_PRINT(buf, (int)sizeof(buf));
        pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
                EVP_AEAD_TLS1_AAD_LEN, &buf[0]);
        printf("AAAAAAAAAAAAAAAAAAAAAAAa, pad = %d, in_len = %d\n", pad, in_len);
    } else {
        printf("notAAAAAAAAAAAAAAAAAAAAAAAa\n");
    }
    printf("------------------Before decrypt--------------------\n");
    CT_PRINT(in, in_len);
    EVP_Cipher(ds, out, in, in_len);
    printf("------------------After decrypt--------------------\n");
    CT_PRINT(out, in_len);
    printf("------------------Remove padding--------------------\n");
    *olen = in_len;
    ret = tls1_cbc_remove_padding(ssl, out, olen, bs, ssl->sc_mac_secret_size);
    if (ret < 0) {
        return ret;
    }
    *olen -= pad;
    CT_PRINT(out, *olen);
    printf("--------------------------------------\n");

    return 0;
}

int
tls1_get_record(ssl_conn_t *ssl, int type, const unsigned char *in, uint32_t len)
{
    EVP_MD_CTX          *hash = NULL;
    uint32_t            clen = len;

    hash = ssl->sc_curr->hc_read_hash;
 
    if (ssl->sc_tlsext_use_etm && hash) {
        CT_LOG("use etm = %d, clen = %d\n", ssl->sc_tlsext_use_etm, clen);
        assert(clen > EVP_MD_CTX_size(hash));
        clen -= EVP_MD_CTX_size(hash);
    }

    tls1_enc(ssl, type, ssl->sc_data, &ssl->sc_data_len, in, clen);

    return len - ssl->sc_data_len;
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
    int                 padding_len = 0;

    h = data;
    if (ssl->sc_renego) {
        padding_len = tls1_get_record(ssl, SSL3_RT_HANDSHAKE, (void *)h, len);
        h = (void *)&ssl->sc_data[0];
        len -= padding_len;
    }
 
    if (h->hk_type <= SSL3_MT_CLIENT_KEY_EXCHANGE) {
        memcpy(&ssl->sc_handshake_msg[ssl->sc_handshake_msg_offset], h, len);
        ssl->sc_handshake_msg_offset += len;
    }

    while (offset < len) {
        change_cipher_spec = ssl->sc_curr->hc_change_cipher_spec;
        CT_LOG("server %d, ch = %d\n", !client, change_cipher_spec);
        if (change_cipher_spec == true && ssl->sc_renego == 0) {
            padding_len = tls1_get_record(ssl, SSL3_RT_HANDSHAKE,
                    (void *)h, len - offset);
            h = (void *)&ssl->sc_data[0];
            len -= padding_len;
        }
        mlen = ntohl(get_len_3byte(h->hk_len));
        CT_LOG("%s: type = %d, len = %d\n", client?"client":"server",h->hk_type, mlen);
        if (ssl->sc_renego) {
            CT_LOG("Renego handshake\n");
        }
        if (h->hk_type >= TLS1_2_HANDSHAKE_HANDLER_NUM) {
            CT_LOG("Unknown type = %d\n", h->hk_type);
            goto out;
        }

        proc = tls1_2_handshake_handler[h->hk_type];
        if (proc == NULL) {
            CT_LOG("Unsupported type = %d\n", h->hk_type);
            goto out;
        }

        pkt.curr = (void *)(h + 1);
        pkt.remaining = mlen;
        if (proc(ssl, &pkt) < 0) {
            goto out;
        }

        offset += mlen + sizeof(*h);
        h = (void *)((char *)(h + 1) + mlen);
    }

    return 0;
out:
    connection_free((connection_t *)ssl);
    return -1;
}

int
tls1_2_application_data_proc(ssl_conn_t *ssl, void *data, uint16_t len,
            int client)
{
    char    *side = NULL;
    char    split_str[CT_CMD_BUF_SIZE] = {};

    tls1_get_record(ssl, SSL3_RT_APPLICATION_DATA, data, len);
    side = client ? "client" : "server";
    snprintf(split_str, sizeof(split_str),
            "\n============%s start============\n", side);
    //fwrite(split_str, strlen(split_str), 1, ssl->sc_conn.tp_output);

    fwrite(ssl->sc_data, ssl->sc_data_len, 1, ssl->sc_conn.tp_output);

    snprintf(split_str, sizeof(split_str),
            "\n============%s end[%d]============\n", side, ssl->sc_data_len);
    //fwrite(split_str, strlen(split_str), 1, ssl->sc_conn.tp_output);
    return 0;
}

int
tls1_2_alert_proc(ssl_conn_t *ssl, void *data, uint16_t len, int client)
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

    if (conn->hc_read_hash) {
        EVP_MD_CTX_free(conn->hc_read_hash);
        conn->hc_read_hash = NULL;
    }

    if (conn->hc_key_block) {
        free(conn->hc_key_block);
        conn->hc_key_block = NULL;
    }
    if (tls1_setup_key_block(ssl) != 0) {
        return -1;
    }

    p = conn->hc_key_block;
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
    conn->hc_read_hash = EVP_MD_CTX_new();
    if (conn->hc_read_hash == NULL) {
        CT_LOG("New MD CTX failed!\n");
        return -1;
    }

    mac_ctx = conn->hc_read_hash;
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
    if ((EVP_CIPHER_flags(ssl->sc_evp_cipher) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        CT_LOG("AEADDDDDDDDDDDDDDDDDDDddd\n");
    }

    return 0;
}

