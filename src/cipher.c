#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/comp.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include "ssl.h"
#include "cipher.h"
#include "log.h"

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
    const EVP_MD *md = EVP_get_digestbynid(ssl->sc_cipher->sp_md_nid);
    EVP_PKEY_CTX *pctx = NULL;

    int ret = -1;
    size_t outlen = olen;

    if (md == NULL) {
        /* Should never happen */
        CT_LOG("Get MD(%d) failed!\n", ssl->sc_cipher->sp_md_nid);
        return -1;
    }
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
    CT_PRINT(p, SSL_MAX_MASTER_KEY_LENGTH);

    if (tls1_PRF(ssl,
            TLS_MD_MASTER_SECRET_CONST,
            TLS_MD_MASTER_SECRET_CONST_SIZE,
            ssl->sc_client_random, SSL3_RANDOM_SIZE,
            NULL, 0,
            ssl->sc_server_random, SSL3_RANDOM_SIZE,
            NULL, 0, p, SSL_MAX_MASTER_KEY_LENGTH, ssl->sc_master_key,
            SSL_MAX_MASTER_KEY_LENGTH) != 0) {
        CT_LOG("Generate master key failed!\n");
        return -1;
    }

    ssl->sc_master_key_length = SSL_MAX_MASTER_KEY_LENGTH;

    return 0;
}

int
ssl_cipher_get_evp(const ssl_conn_t *ssl, const EVP_CIPHER **enc,
    const EVP_MD **md, int *mac_pkey_type, int *mac_secret_size)
{
    ssl_cipher_t        *cipher = ssl->sc_cipher;

    *enc = EVP_get_cipherbynid(cipher->sp_cipher_nid);
    if (*enc == NULL) {
        CT_LOG("Get cipher by nid %x failed\n", cipher->sp_id);
        return -1;
    }
    *md = EVP_get_digestbynid(cipher->sp_md_nid);
    assert(*md != NULL);
    *mac_secret_size = EVP_MD_size(*md);
    *mac_pkey_type = EVP_PKEY_HMAC;

    return 0;
}

int
tls1_setup_key_block(ssl_conn_t *ssl)
{
    unsigned char       *p = NULL;
    const EVP_CIPHER    *c = NULL;
    const EVP_MD        *hash = NULL;
    int                 num = 0;
    int                 mac_type = NID_undef;
    int                 mac_secret_size = 0;

    if (ssl_cipher_get_evp(ssl, &c,  &hash, &mac_type,
                &mac_secret_size) != 0) {
        CT_LOG("Get evp failed\n");
        return -1;
    }

    num = EVP_CIPHER_key_length(c) + mac_secret_size + EVP_CIPHER_iv_length(c);
    num *= 2;
    if ((p = malloc(num)) == NULL) {
        CT_LOG("Malloc %d bytes failed\n", num);
        return -1;
    }

    ssl->sc_key_block = p;
    ssl->sc_key_block_length = num;

    CT_LOG("key block len = %d\n", num);
    return tls1_PRF(ssl,
            TLS_MD_KEY_EXPANSION_CONST,
            TLS_MD_KEY_EXPANSION_CONST_SIZE,
            ssl->sc_server_random, SSL3_RANDOM_SIZE,
            ssl->sc_client_random, SSL3_RANDOM_SIZE,
            NULL, 0, NULL, 0, ssl->sc_master_key, 
            ssl->sc_master_key_length, p, num);
}

