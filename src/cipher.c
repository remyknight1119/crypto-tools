#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include "ssl.h"
#include "cipher.h"
#include "log.h"


int
tls_process_cke_rsa(ssl_conn_t *ssl, PACKET *pkt)
{
    pre_master_secret_t     *secret = NULL;
    RSA                     *rsa = rsa_private_key;
    uint16_t                *len = pkt->data;
    int                     decrypt_len = 0;

    secret = &ssl->sc_pre_master;
    secret->pm_len = ntohs(*len);
    assert(secret->pm_len + sizeof(*len) == pkt->remaining);

    assert(rsa != NULL);
    if (RSA_size(rsa) < SSL_MAX_MASTER_KEY_LENGTH) {
        CT_LOG("RSA size(%d) is too big!\n", RSA_size(rsa));
        return -1;
    }

    decrypt_len = RSA_private_decrypt(secret->pm_len, (void *)(len + 1),
            secret->pm_pre_master, rsa, RSA_NO_PADDING);
    if (decrypt_len < 0) {
        CT_LOG("RSA decrypt failed!\n");
        return -1;
    }

    return 0;
}
