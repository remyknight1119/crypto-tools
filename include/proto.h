#ifndef __CT_PROTO_H__
#define __CT_PROTO_H__

#include "list.h"

typedef void (*proto_handler)(void *header);

typedef struct _proto_net_t {
    struct list_head    pn_list;
    uint16_t            pn_type;
    proto_handler       pn_handler;
} proto_net_t;

extern void proto_net_register(proto_net_t *proto);
extern proto_handler proto_find_handler(uint16_t type);
extern void proto_init(void);

#endif
