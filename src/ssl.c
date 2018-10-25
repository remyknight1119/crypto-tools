#include <assert.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>

#include  "ssl.h"
#include  "log.h"
#include  "record.h"
#include  "tls1.h"

#define RECORD_PROC_MAX     256

typedef struct _ssl_proto_t {
    uint16_t        pt_version;
    record_proc_f   *pt_handler;
    size_t           pt_hnum;
} ssl_proto_t;

static record_proc_f tls1_2_handler[] = {
    NULL, /* 0 */
    NULL, /* 1 */
    NULL, /* 2 */
    NULL, /* 3 */
    NULL, /* 4 */
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
    NULL, /* 16 */
    NULL, /* 17 */
    NULL, /* 18 */
    NULL, /* 19 */
    tls1_2_change_cipher_spec_proc, /* 20 */
    tls1_2_alert_proc, /* 21 */
    tls1_2_handshake_proc, /* 22 */
    tls1_2_application_data_proc, /* 23 */
};

#define TLS1_2_HANDLER_NUM  CT_ARRAY_SIZE(tls1_2_handler)

static ssl_proto_t proto_handler[] = {
    {
        .pt_version = TLS1_VERSION,
        .pt_handler = tls1_2_handler,
        .pt_hnum = TLS1_2_HANDLER_NUM,
    },
    {
        .pt_version = TLS1_1_VERSION,
        .pt_handler = tls1_2_handler,
        .pt_hnum = TLS1_2_HANDLER_NUM,
    },
    {
        .pt_version = TLS1_2_VERSION,
        .pt_handler = tls1_2_handler,
        .pt_hnum = TLS1_2_HANDLER_NUM,
    },
};

#define SSL_PROTO_HANDLER_NUM   CT_ARRAY_SIZE(proto_handler)

static ssl_cipher_t ssl_cipher[] = {
    {
        .sp_id = TLS1_CK_RSA_WITH_AES_128_SHA,
        .sp_algorithm_mkey = SSL_kRSA,
        .sp_algorithm_enc = SSL_AES128,
        .sp_algorithm_mac = SSL_SHA1,
        .sp_cipher_nid = NID_aes_128_cbc,
        .sp_mac_nid = NID_sha1,
        .sp_md_nid = NID_sha256,
    },
    {
        .sp_id = TLS1_CK_RSA_WITH_AES_256_SHA,
        .sp_algorithm_mkey = SSL_kRSA,
        .sp_algorithm_enc = SSL_AES256,
        .sp_algorithm_mac = SSL_SHA1,
        .sp_cipher_nid = NID_aes_256_cbc,
        .sp_mac_nid = NID_sha1,
        .sp_md_nid = NID_sha256,
    },
    {
        .sp_id = TLS1_CK_RSA_WITH_AES_128_SHA256,
        .sp_algorithm_mkey = SSL_kRSA,
        .sp_algorithm_enc = SSL_AES128,
        .sp_algorithm_mac = SSL_SHA256,
        .sp_cipher_nid = NID_aes_128_cbc,
        .sp_mac_nid = NID_sha256,
        .sp_md_nid = NID_sha256,
    },
    {
        .sp_id = TLS1_CK_RSA_WITH_AES_256_SHA256,
        .sp_algorithm_mkey = SSL_kRSA,
        .sp_algorithm_enc = SSL_AES256,
        .sp_algorithm_mac = SSL_SHA256,
        .sp_cipher_nid = NID_aes_256_cbc,
        .sp_mac_nid = NID_sha256,
        .sp_md_nid = NID_sha256,
    },
};

#define SSL_CIPHER_NUM      CT_ARRAY_SIZE(ssl_cipher)

RSA *rsa_private_key;

static int
ssl_record_proc(ssl_conn_t *ssl, record_t *r, int client)
{
    record_proc_f   *rp = NULL;
    record_proc_f   handler = NULL;
    uint16_t        version = 0;
    int             i = 0;

    ssl->sc_curr = client ? &ssl->sc_client : &ssl->sc_server;
    version = ntohs(r->rd_version);
    ssl->sc_version = version;
    ssl->sc_explicit_iv = (version == TLS1_2_VERSION);
    for (i = 0; i < SSL_PROTO_HANDLER_NUM; i++) {
        if (proto_handler[i].pt_version == version) {
            if (r->rd_type >= proto_handler[i].pt_hnum) {
                CT_LOG("Invalid type = %d\n", r->rd_type);
                return -1;
            }
            rp = proto_handler[i].pt_handler;
            handler = rp[r->rd_type];
            if (handler == NULL) {
                CT_LOG("Unknown type = %d\n", r->rd_type);
                return -1;
            }
            return handler(ssl, r + 1, ntohs(r->rd_len), client);
        }
    }

    CT_LOG("Unknown version %x\n", version);
    return -1;
}

void
ssl_msg_proc(connection_t *conn, void *record, uint16_t len, int client)
{
    record_t        *r = NULL;
    ssl_conn_t      *ssl = NULL;
    ssl_buffer_t    *buffer = NULL;
    uint16_t        rlen = 0;
    uint16_t        wlen = 0;
    uint16_t        tlen = 0;

    ssl = (void *)conn;
    buffer = client ? &ssl->sc_client_buffer : &ssl->sc_server_buffer;
    if (buffer->bf_need_len > 0) {
        wlen = len > buffer->bf_need_len ? buffer->bf_need_len : len;
        memcpy(&buffer->bf_data[buffer->bf_offset], record, wlen);
        buffer->bf_offset += len;
        buffer->bf_need_len -= wlen;
        len -= wlen;
        if (buffer->bf_need_len > 0) {
            assert(len == 0);
#if 0
            CT_LOG("Need more data, need len = %d, wlen = %d, len = %d\n",
                    buffer->bf_need_len, wlen, len);
#endif
            return;
        }
        buffer->bf_offset = 0;
        record = (char *)record + wlen;
        ssl_record_proc(ssl, (void *)&buffer->bf_data[0], client);
        if (len == 0) {
            return;
        }
    }

    r = record;
    //CT_LOG("record =  %x %x %x\n", r->rd_type, r->rd_version, r->rd_len);
    rlen = ntohs(r->rd_len);
    tlen = rlen + sizeof(*r);
    if (tlen <= len) {
        ssl_record_proc(ssl, record, client);
        if (tlen < len) {
            ssl_msg_proc(conn, (char *)record + tlen, len - tlen, client);
        }
        return;
    }
    memcpy(&buffer->bf_data[0], record, len);
    buffer->bf_offset = len;
    buffer->bf_need_len = rlen - (len - sizeof(*r));
    //CT_LOG("Wait more data, rlen = %d, len = %d, need len = %d\n", rlen, len, buffer->bf_need_len);
}

ssl_cipher_t *
ssl_get_cipher_by_id(uint32_t id)
{
    int     i = 0;

    for (i = 0; i < SSL_CIPHER_NUM; i++) {
        if ((ssl_cipher[i].sp_id & 0xFFFF) == id) {
            return &ssl_cipher[i];
        }
    }

    return NULL;
}

int
ssl_init(const char *file)
{
    BIO     *in = NULL;
    int     ret = -1;

    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_256_ccm());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());

    EVP_add_digest(EVP_sha1());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha512());

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        CT_LOG("New BIO failed\n");
        goto out;
    }

    if (BIO_read_filename(in, file) <= 0) {
        CT_LOG("Read %s failed\n", file);
        goto out;
    }

    rsa_private_key = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);
    if (rsa_private_key == NULL) {
        CT_LOG("Load key freom %s failed\n", file);
        goto out;
    }

    ret = 0;
out:
    BIO_free(in);
    return ret;
}
