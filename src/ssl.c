#include <openssl/ssl3.h>

#include  "ssl.h"
#include  "log.h"
#include  "record.h"

#define RECORD_PROC_MAX     256

typedef int (*record_proc_f)(ssl_conn_t *conn, void *data, uint16_t len);

static record_proc_f record_proc[RECORD_PROC_MAX];

static int ssl_application_data_proc(ssl_conn_t *conn,
            void *data, uint16_t len);
static int ssl_alert_proc(ssl_conn_t *conn, void *data, uint16_t len);
static int ssl_change_cipher_spec_proc(ssl_conn_t *conn,
            void *data, uint16_t len);

static void
ssl_record_proc_init(void)
{
    record_proc[SSL3_RT_HANDSHAKE] = ssl_handshake_proc;
    record_proc[SSL3_RT_APPLICATION_DATA] = ssl_application_data_proc;
    record_proc[SSL3_RT_ALERT] = ssl_alert_proc;
    record_proc[SSL3_RT_CHANGE_CIPHER_SPEC] = ssl_change_cipher_spec_proc;
}

void
ssl_msg_proc(connection_t *conn, void *record, uint16_t len)
{
    record_t        *r = NULL;
    record_proc_f   rp = NULL;
    ssl_conn_t      *ssl = NULL;

    ssl_record_proc_init();
    r = record;
    ssl = (void *)conn;
    CT_LOG("type = %d, len = %d\n", r->rd_type, ntohs(r->rd_len));
    if (r->rd_type >= RECORD_PROC_MAX) {
        return;
    }

    rp = record_proc[r->rd_type];
    if (rp == NULL) {
        return;
    }

    rp(ssl, r + 1, ntohs(r->rd_len));
}

static int
ssl_application_data_proc(ssl_conn_t *conn, void *data, uint16_t len)
{
    return 0;
}

static int
ssl_alert_proc(ssl_conn_t *conn, void *data, uint16_t len)
{
    return 0;
}

static int
ssl_change_cipher_spec_proc(ssl_conn_t *conn, void *data, uint16_t len)
{
    return 0;
}


