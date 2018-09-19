
#include "record.h"
#include "ssl.h"
#include "log.h"

int
ssl_handshake_proc(ssl_conn_t *conn, void *data, uint16_t len)
{
    handshake_t     *h = NULL;

    h = data;
    CT_LOG("type = %d\n", h->hk_type);
    
    return 0;
}
