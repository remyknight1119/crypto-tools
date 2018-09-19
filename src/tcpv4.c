#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "log.h"
#include "connect.h"

void tcp_v4_handler(uint32_t daddr, uint32_t saddr, void *proto_header)
{
    struct tcphdr   *th = proto_header;
    struct in_addr  dip = {};
    struct in_addr  sip = {};
        
    dip.s_addr = daddr;
    sip.s_addr = saddr;
    CT_LOG("%s[%d]--->%s[%d]\n", inet_ntoa(sip), ntohs(th->th_sport),
            inet_ntoa(dip), ntohs(th->th_dport));
}
