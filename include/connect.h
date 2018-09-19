#ifndef __CT_CONNECT_H__
#define __CT_CONNECT_H__

#include "ip.h"
#include "list.h"
#include "log.h"

typedef struct _connection_key_t {
    ip_addr_t   ck_saddr;
    ip_addr_t   ck_daddr;
    uint16_t    ck_sport;
    uint16_t    ck_dport;
} connection_key_t;

typedef struct _connection_t {
    struct list_head    ct_list;
    connection_key_t    ct_key;
    uint8_t             ct_state;
} connection_t;

static inline void conn_key_print(connection_key_t key)
{
    uint8_t     src[4] = {};
    uint8_t     dst[4] = {};

    memcpy(src, &key.ck_saddr.pa_addr4.s_addr, sizeof(src));
    memcpy(dst, &key.ck_daddr.pa_addr4.s_addr, sizeof(dst));
    CT_LOG("%d.%d.%d.%d[%d]--->%d.%d.%d.%d[%d]\n",
            src[0], src[1], src[2], src[3],
            key.ck_sport,
            dst[0], dst[1], dst[2], dst[3],
            key.ck_dport);
} 
 
extern connection_t *connection_find(connection_key_t key, int *client,
            struct list_head *head);
extern connection_t *connection_alloc(size_t size, struct list_head *head);
extern void connection_free(connection_t *conn);

#endif
