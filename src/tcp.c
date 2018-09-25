#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "log.h"
#include "connect.h"

LIST_HEAD(tcp_conn_list);

tcp_conn_t *
tcp_conn_find(connection_key_t key, int *client)
{
    connection_t    *conn = connection_find(key, client, &tcp_conn_list);

    return (tcp_conn_t *)conn;
}

tcp_conn_t *
tcp_conn_alloc(size_t size)
{
    connection_t    *conn = NULL;

    conn = connection_alloc(size, &tcp_conn_list);
    return (tcp_conn_t *)conn;
}

void
tcp_conn_free(tcp_conn_t *conn)
{
    connection_free((connection_t *)conn);
}