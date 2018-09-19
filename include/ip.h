#ifndef __CT_IPV4_H__
#define __CT_IPV4_H__

#include <netinet/in.h>

typedef struct _ip_addr_t {
    union {
        struct in_addr      pa_addr4;
        struct in6_addr     pa_addr6;
    };
} ip_addr_t;

typedef void (*ipv4_next_proto_handler)(uint32_t daddr, uint32_t saddr,
            void *proto_header);

extern void ipv4_handler(void *header);
extern void ipv4_proto_register(ipv4_next_proto_handler handler,
            uint8_t proto);
extern void ipv4_init(void);


#endif
