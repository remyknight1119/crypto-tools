#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "connect.h"
#include "log.h"

connection_t *
connection_find(connection_key_t key, int *client, struct list_head *head)
{
    struct list_head    *pos = NULL;
    connection_t        *conn = NULL;
    connection_key_t    reverse = {
        .ck_saddr = key.ck_daddr,
        .ck_daddr = key.ck_saddr,
        .ck_sport = key.ck_dport,
        .ck_dport = key.ck_sport,
    };

    list_for_each(pos, head) {
        conn = list_entry(pos, connection_t, ct_list);
        if (memcmp(&conn->ct_key, &key, sizeof(key)) == 0) {
            if (client != NULL) {
                *client = 1;
            }
            return conn;
        }
        if (memcmp(&conn->ct_key, &reverse, sizeof(reverse)) == 0) {
            if (client != NULL) {
                *client = 0;
            }
            return conn;
        }
    }

    return NULL;
}

connection_t *
connection_alloc(size_t size, struct list_head *head)
{
    connection_t    *conn = NULL;

    assert(size >= sizeof(*conn));

    conn = calloc(1, size);
    if (conn == NULL) {
        return NULL;
    }

    list_add_tail(&conn->ct_list, head);

    return conn;
}

void
connection_free(connection_t *conn)
{
    list_del(&conn->ct_list);
    free(conn);
}
