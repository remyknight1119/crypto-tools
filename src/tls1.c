#include <assert.h>
#include <openssl/ssl3.h>

#include  "ssl.h"
#include  "log.h"
#include  "record.h"
#include  "tls1.h"


typedef int (*handshake_proc_f)(ssl_conn_t *conn, void *data,
            uint16_t len, int client);
static int tls1_2_hello_request(ssl_conn_t *conn, void *data,
            uint16_t len, int client);
static int tls1_2_client_hello(ssl_conn_t *conn, void *data,
            uint16_t len, int client);
static int tls1_2_server_hello(ssl_conn_t *conn, void *data,
            uint16_t len, int client);

static handshake_proc_f tls1_2_handshake_handler[] = {
    tls1_2_hello_request, /* 0 */
    tls1_2_client_hello, /* 1 */
    tls1_2_server_hello, /* 2 */
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
    NULL, /* 20 */
    NULL, /* 21 */
    NULL, /* 22 */
};

#define TLS1_2_HANDSHAKE_HANDLER_NUM    CT_ARRAY_SIZE(tls1_2_handshake_handler)

static int
tls1_2_hello_request(ssl_conn_t *conn, void *data, uint16_t len, int client)
{
    conn->sc_renego = 1;
    return 0;
}

static int
tls1_2_client_hello(ssl_conn_t *conn, void *data, uint16_t len, int client)
{
    client_hello_t      *h = data;

    assert(len >= sizeof(*h));
    memcpy(conn->sc_client_random, h->ch_random.rm_random_bytes,
            sizeof(conn->sc_client_random));

    return 0;
}

static int
tls1_2_server_hello(ssl_conn_t *conn, void *data, uint16_t len, int client)
{
    server_hello_t      *h = data;
    uint8_t             *p = NULL;

    assert(len >= sizeof(*h));
    memcpy(conn->sc_server_random, h->sh_random.rm_random_bytes,
            sizeof(conn->sc_server_random));
    CT_LOG("random = %x %x %x %x\n", conn->sc_server_random[0],
            conn->sc_server_random[1],conn->sc_server_random[2],conn->sc_server_random[3]);
    p = (void *)&h->sh_session_id[0];
    p += h->sh_session_id_len;
    conn->sc_cipher = ntohs(*((uint16_t *)p));

    CT_LOG("cipher = %x\n", conn->sc_cipher);
    return 0;
}

int
tls1_2_handshake_proc(ssl_conn_t *conn, void *data, uint16_t len, int client)
{
    handshake_t         *h = NULL;
    handshake_proc_f    proc = NULL;
    uint16_t            offset = 0;
    uint32_t            mlen = 0;

    h = data;
    while (offset < len) {
        mlen = ntohl(get_len_3byte(h->hk_len));
        CT_LOG("%s: type = %d, len = %d\n", client?"client":"server",h->hk_type, mlen);
        if (conn->sc_renego) {
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

        if (proc(conn, h + 1, mlen, client) < 0) {
            return -1;
        }

        offset += mlen + sizeof(*h);
        h = (void *)((char *)(h + 1) + mlen);
    }

    return 0;
}

int
tls1_2_application_data_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int lcient)
{
    return 0;
}

int
tls1_2_alert_proc(ssl_conn_t *conn, void *data, uint16_t len, int lcient)
{
    return 0;
}

int
tls1_2_change_cipher_spec_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int lcient)
{
    return 0;
}

