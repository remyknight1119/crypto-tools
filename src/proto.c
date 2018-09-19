#include <net/ethernet.h>

#include "proto.h"
#include "ip.h"

LIST_HEAD(proto_net_list);

static proto_net_t proto_ipv4 = {
    .pn_type = ETHERTYPE_IP,
    .pn_handler = ipv4_handler,
};

void
proto_net_register(proto_net_t *proto)
{
    list_add_tail(&proto->pn_list, &proto_net_list);
}

proto_handler
proto_find_handler(uint16_t type)
{
    struct list_head    *pos = NULL;
    proto_net_t         *proto = NULL;

    list_for_each(pos, &proto_net_list) {
        proto = list_entry(pos, proto_net_t, pn_list);
        if (proto->pn_type == type) {
            return proto->pn_handler;
        }
    }

    return NULL;
}

void
proto_init(void)
{
    proto_net_register(&proto_ipv4);
    ipv4_init();
}
