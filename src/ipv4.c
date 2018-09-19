#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "ip.h"
#include "tcp.h"
#include "log.h"

#define NEXT_PROTO_MAX  256

static ipv4_next_proto_handler proto_handler[NEXT_PROTO_MAX];

void
ipv4_handler(void *header)
{
    struct iphdr            *ip = header;
    uint16_t                hlen = 0;
    ipv4_next_proto_handler handler = NULL;

    if (ip->protocol >= NEXT_PROTO_MAX) {
        return;
    }

    handler = proto_handler[ip->protocol];
    if (handler == NULL) {
        CT_LOG("No handler for protocol %d\n", ip->protocol);
        return;
    }

    hlen = ip->ihl*4;
    handler(ip->daddr, ip->saddr, (char *)ip + hlen, ntohs(ip->tot_len) - hlen);
}

void
ipv4_proto_register(ipv4_next_proto_handler handler, uint8_t proto)
{
    if (proto >= NEXT_PROTO_MAX) {
        return;
    }

    proto_handler[proto] = handler;
}

void
ipv4_init(void)
{
    ipv4_proto_register(tcp_v4_handler, IPPROTO_TCP);
}
