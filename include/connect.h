#ifndef __CT_CONNECT_H__
#define __CT_CONNECT_H__

#include "ip.h"
#include "list.h"

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

extern connection_t *connection_find(connection_key_t key, struct list_head *head);
extern connection_t *connection_alloc(size_t size, struct list_head *head);
extern void connection_free(connection_t *conn);

#endif
