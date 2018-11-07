#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/comp.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include "ssl.h"
#include "tls1.h"
#include "cipher.h"
#include "log.h"

static const EVP_MD *
tls1_get_md(ssl_conn_t *ssl)
{
    int         md_nid = 0;

    md_nid = ssl->sc_cipher->sp_md_nid;
    if (ssl->sc_version < TLS1_2_VERSION) {
        switch (md_nid) {
            case NID_sha256:
                md_nid = NID_md5_sha1;
                break;
            default:
                break;
        }
    }

    return EVP_get_digestbynid(md_nid);
}

/* seed1 through seed5 are concatenated */
static int
tls1_PRF(ssl_conn_t *ssl,
            const void *seed1, int seed1_len,
            const void *seed2, int seed2_len,
            const void *seed3, int seed3_len,
            const void *seed4, int seed4_len,
            const void *seed5, int seed5_len,
            const unsigned char *sec, int slen,
            unsigned char *out, int olen)
{
    const EVP_MD *md = tls1_get_md(ssl);
    EVP_PKEY_CTX *pctx = NULL;
    int *type = (int *)md;

    int ret = -1;
    size_t outlen = olen;

    if (md == NULL) {
        /* Should never happen */
        CT_LOG("Get MD(%d) failed!\n", ssl->sc_cipher->sp_md_nid);
        return -1;
    }
    printf("md->type = %d, md->pkey_type = %d\n", *type, *(type + 1));
    CT_LOG("NID = %d\n", ssl->sc_cipher->sp_md_nid);
    if (seed1)
        CT_PRINT(seed1, seed1_len);
    if (seed2)
        CT_PRINT(seed2, seed2_len);
    if (seed3)
        CT_PRINT(seed3, seed3_len);
    if (seed4)
        CT_PRINT(seed4, seed4_len);
    if (seed5)
        CT_PRINT(seed5, seed5_len);
    CT_PRINT(sec, slen);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
        || EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, slen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, seed1_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, seed2_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, seed3_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, seed4_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, seed5_len) <= 0)
        goto err;

    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0)
        goto err;
    ret = 0;

 err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int
tls1_digest_cached_records(ssl_conn_t *ssl)
{
    EVP_MD_CTX          **dgst = NULL;
    const EVP_MD        *md = NULL;
    void                *hdata = NULL;
    uint32_t            hlen = 0;

    dgst = &ssl->sc_curr->hc_handshake_dgst;
    if (*dgst == NULL) {
        hdata = ssl->sc_handshake_msg;
        hlen = ssl->sc_handshake_msg_offset;
        //CT_PRINT(hdata, hlen);
        *dgst = EVP_MD_CTX_new();
        if (*dgst == NULL) {
            return -1;
        }
        md = tls1_get_md(ssl);
        if (md == NULL || !EVP_DigestInit_ex(*dgst, md, NULL) ||
                !EVP_DigestUpdate(*dgst, hdata, hlen)) {
            return -1;
        }
    }

    return 0;
}

int
tls1_handshake_hash(ssl_conn_t *ssl, unsigned char *out, size_t outlen,
         size_t *hashlen)
{
    EVP_MD_CTX  *ctx = NULL;
    EVP_MD_CTX  *dgst = NULL;
    int         hashleni = 0;
    int         ret = -1;

    dgst = ssl->sc_curr->hc_handshake_dgst;
    hashleni = EVP_MD_CTX_size(dgst);
    if (hashleni < 0 || (size_t)hashleni > outlen) {
        CT_LOG("hash len error!\n");
        goto err;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto err;
    }

    if (!EVP_MD_CTX_copy_ex(ctx, dgst) ||
            EVP_DigestFinal_ex(ctx, out, NULL) <= 0) {
        CT_LOG("Evp failed!\n");
        goto err;
    }
    *hashlen = hashleni;

    ret = 0;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int
tls_generate_master_secret(ssl_conn_t *ssl, const unsigned char *p, int len)
{
    size_t                  hashlen = 0;
    unsigned char           hash[EVP_MAX_MD_SIZE * 2] = {};

    CT_LOG("\n===================================================\n");
    if (ssl->sc_ext_master_secret) {
        if (tls1_digest_cached_records(ssl) != 0) {
            CT_LOG("tls1_digest_cached_records failed!\n");
            return -1;
        }
        
        if (tls1_handshake_hash(ssl, hash, sizeof(hash),
                &hashlen) != 0) {
            CT_LOG("tls1_handshake_hash failed!\n");
            return -1;
        }
        CT_PRINT(hash, (int)hashlen);
        tls1_PRF(ssl,
            TLS_MD_EXTENDED_MASTER_SECRET_CONST,
            TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE,
            hash, hashlen,
            NULL, 0,
            NULL, 0,
            NULL, 0, p, len, ssl->sc_master_key,
            SSL_MAX_MASTER_KEY_LENGTH);
        CT_LOG("ext master secret:\n");
    } else {
        tls1_PRF(ssl,
            TLS_MD_MASTER_SECRET_CONST,
            TLS_MD_MASTER_SECRET_CONST_SIZE,
            ssl->sc_client_random, SSL3_RANDOM_SIZE,
            NULL, 0,
            ssl->sc_server_random, SSL3_RANDOM_SIZE,
            NULL, 0, p, len, ssl->sc_master_key,
            SSL_MAX_MASTER_KEY_LENGTH);
        CT_LOG("Generate master key:\n");
    }

    ssl->sc_master_key_length = SSL_MAX_MASTER_KEY_LENGTH;
    CT_PRINT(ssl->sc_master_key, ssl->sc_master_key_length);
    CT_LOG("\n===================================================\n");

    return 0;
}

int
tls_process_cke_use_log(ssl_conn_t *ssl, PACKET *pkt)
{
    if (ssl->sc_random_master_key == NULL) {
        CT_LOG("Pre Master Key is NULL\n");
        return -1;
    }

    memcpy(ssl->sc_master_key, ssl->sc_random_master_key->master_key,
            sizeof(ssl->sc_master_key));

    ssl->sc_master_key_length = sizeof(ssl->sc_master_key);
    return 0;
}

int
tls_process_cke_rsa(ssl_conn_t *ssl, PACKET *pkt)
{
    RSA                     *rsa = rsa_private_key;
    uint16_t                *len = pkt->data;
    const unsigned char     *p = NULL;
    int                     decrypt_len = 0;
    int                     padding_len = 0;
    pre_master_secret_t     secret = {};

    secret.pm_len = ntohs(*len);
    assert(secret.pm_len + sizeof(*len) == pkt->remaining);

    assert(rsa != NULL);
    if (RSA_size(rsa) < SSL_MAX_MASTER_KEY_LENGTH) {
        CT_LOG("RSA size(%d) is too small!\n", RSA_size(rsa));
        return -1;
    }

    decrypt_len = RSA_private_decrypt(secret.pm_len, (void *)(len + 1),
            secret.pm_pre_master, rsa, RSA_NO_PADDING);
    if (decrypt_len < 0) {
        CT_LOG("RSA decrypt failed!\n");
        return -1;
    }

    padding_len = decrypt_len - SSL_MAX_MASTER_KEY_LENGTH;
    p = (void *)&secret.pm_pre_master[padding_len];

    return tls_generate_master_secret(ssl, p, SSL_MAX_MASTER_KEY_LENGTH);
}

int
ssl_cipher_get_evp(ssl_conn_t *ssl, const EVP_CIPHER **enc,
    const EVP_MD **md, int *mac_pkey_type, int *mac_secret_size,
    int use_etm)
{
    ssl_cipher_t        *cipher = ssl->sc_cipher;
    const EVP_CIPHER    *evp = NULL;

    *enc = EVP_get_cipherbynid(cipher->sp_cipher_nid);
    if (*enc == NULL) {
        CT_LOG("Get cipher by nid %x failed\n", cipher->sp_id);
        return -1;
    }
    *md = EVP_get_digestbynid(cipher->sp_mac_nid);
    if (cipher->sp_algorithm_mac == SSL_AEAD) {
        mac_pkey_type = NULL;
        *mac_secret_size = 0;
        *md = NULL;
        ssl->sc_tlsext_use_etm = 0;
        use_etm = 0;
    } else {
        *mac_pkey_type = EVP_PKEY_HMAC;
        *mac_secret_size = EVP_MD_size(*md);
    }
        
    CT_LOG("md nid = %d\n", cipher->sp_mac_nid);
    if ((*enc != NULL) && (*md != NULL || (EVP_CIPHER_flags(*enc) & EVP_CIPH_FLAG_AEAD_CIPHER))) {
        CT_LOG("EEEEEEEEEEEEEEEEEEEEee\n");
        if (use_etm) {
            return 0;
        }

        if (cipher->sp_algorithm_enc == SSL_AES128 &&
                cipher->sp_algorithm_mac == SSL_SHA1 &&
                (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA1"))) {
            CT_LOG("EVP\n");
            *enc = evp, *md = NULL;
       } else if (cipher->sp_algorithm_enc == SSL_AES256 &&
                cipher->sp_algorithm_mac == SSL_SHA1 &&
                (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA1"))) {
            CT_LOG("EVP\n");
            *enc = evp, *md = NULL;
       } else if (cipher->sp_algorithm_enc == SSL_AES128 &&
                cipher->sp_algorithm_mac == SSL_SHA256 &&
                (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA256"))) {
            CT_LOG("EVP, sha256\n");
            *enc = evp, *md = NULL;
       } else if (cipher->sp_algorithm_enc == SSL_AES256 &&
                cipher->sp_algorithm_mac == SSL_SHA256 &&
                (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA256"))) {
            CT_LOG("EVP\n");
            *enc = evp, *md = NULL;
       }

        assert(*enc != NULL);
        return 0;
    }

    return -1;
}

int
tls1_setup_key_block(ssl_conn_t *ssl)
{
    unsigned char       *p = NULL;
    const EVP_CIPHER    *c = NULL;
    const EVP_MD        *hash = NULL;
    ssl_half_conn_t     *conn = NULL; 
    int                 num = 0;
    int                 mac_type = NID_undef;
    int                 mac_secret_size = 0;

    if (ssl_cipher_get_evp(ssl, &c,  &hash, &mac_type,
                &mac_secret_size, ssl->sc_tlsext_use_etm) != 0) {
        CT_LOG("Get evp failed\n");
        return -1;
    }

    conn = ssl->sc_curr;
    num = EVP_CIPHER_key_length(c) + mac_secret_size + EVP_CIPHER_iv_length(c);
    printf("111 num = %d, keylen = %d, szie = %d, lc = %d\n",
            num, EVP_CIPHER_key_length(c), mac_secret_size, EVP_CIPHER_iv_length(c));
    num *= 2;
    if ((p = malloc(num)) == NULL) {
        CT_LOG("Malloc %d bytes failed\n", num);
        return -1;
    }

    ssl->sc_new_hash = hash;
    ssl->sc_evp_cipher = c;
    conn->hc_key_block = p;
    ssl->sc_key_block_length = num;
    ssl->sc_mac_type = mac_type;
    ssl->sc_mac_secret_size = mac_secret_size;

    CT_LOG("key block:\n");
    int ret = tls1_PRF(ssl,
            TLS_MD_KEY_EXPANSION_CONST,
            TLS_MD_KEY_EXPANSION_CONST_SIZE,
            ssl->sc_server_random, SSL3_RANDOM_SIZE,
            ssl->sc_client_random, SSL3_RANDOM_SIZE,
            NULL, 0, NULL, 0, ssl->sc_master_key, 
            ssl->sc_master_key_length, p, num);

    CT_PRINT(p, num);
    return ret;
}

