#include <assert.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "log.h"
#include "ssl.h"
#include "connect.h"
#include "comm.h"

const char *decrypt_dir;

LIST_HEAD(tcp_conn_list);

tcp_conn_t *
tcp_conn_find(connection_key_t key, int *client)
{
    connection_t    *conn = connection_find(key, client, &tcp_conn_list);

    return (tcp_conn_t *)conn;
}

tcp_conn_t *
tcp_conn_alloc(connection_key_t key)
{
    connection_t    *conn = NULL;
    tcp_conn_t      *tp = NULL;
    FILE            *fp = NULL;
    char            path[CT_CMD_BUF_SIZE] = {};

    assert(decrypt_dir != NULL);
    conn = connection_alloc(sizeof(ssl_conn_t), &tcp_conn_list);
    tp = (tcp_conn_t *)conn;
    tp->tp_conn.ct_key = key;
    snprintf(path, sizeof(path), "%s/%d---%d.txt", decrypt_dir,
            key.ck_sport, key.ck_dport);
    fp = fopen(path, "w");
    if (fp == NULL) {
        CT_LOG("Open %s failed!\n", path);
    }

    tp->tp_output = fp;

    return tp;
}

void
tcp_conn_free(tcp_conn_t *conn)
{
    if (conn->tp_output) {
        fclose(conn->tp_output);
    }
    connection_free((connection_t *)conn);
}
