#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "log.h"
#include "connect.h"
#include "ssl.h"

static void
tcp_statm(struct tcphdr *th, tcp_conn_t *conn, int client)
{
    switch (conn->tp_conn.ct_state) {
        case TCP_STATE_SYN:
            if (th->syn && th->ack) {
                conn->tp_conn.ct_state = TCP_STATE_SYN_ACK;
            }
            break;
        case TCP_STATE_SYN_ACK:
            if (!th->syn && th->ack) {
                conn->tp_conn.ct_state = TCP_STATE_EST;
            }
            break;
        case TCP_STATE_EST:
            if (th->fin) {
                conn->tp_conn.ct_state =
                    client ? TCP_STATE_CLIENT_FIN : TCP_STATE_SERVER_FIN;
            }
            break;
        case TCP_STATE_CLIENT_FIN:
            if (!client && th->fin) {
                tcp_conn_free(conn);
                return;
            }
            break;
        case TCP_STATE_SERVER_FIN:
            if (client && th->fin) {
                tcp_conn_free(conn);
                return;
            }
            break;
        default:
            return;
    }
}

void
tcp_v4_handler(uint32_t daddr, uint32_t saddr, void *proto_header, uint16_t len)
{
    struct tcphdr       *th = proto_header;
    tcp_conn_t          *conn = NULL;
    connection_key_t    key = {};
    uint16_t            hlen = 0;
    uint16_t            plen = 0;
    int                 client = 1;
        
    key.ck_saddr.pa_addr4.s_addr = saddr;
    key.ck_daddr.pa_addr4.s_addr = daddr;
    key.ck_sport = ntohs(th->source);
    key.ck_dport = ntohs(th->dest);

    conn = tcp_conn_find(key, &client);
    if (conn == NULL) {
        if (!th->syn || th->ack) {
            return;
        }
        conn = tcp_conn_alloc(sizeof(ssl_conn_t));
        if (conn == NULL) {
            CT_LOG("Alloc tcp conn failed!\n");
            return;
        }
        conn->tp_conn.ct_key = key;
        conn->tp_conn.ct_state = TCP_STATE_SYN;
        return;
    }

    if (th->rst) {
        tcp_conn_free(conn);
        return;
    }

    hlen = th->doff * 4;
    plen = len - hlen;
    if (plen > 0) {
        ssl_msg_proc((connection_t *)conn, (char *)proto_header + hlen, plen);
        CT_LOG("%s: ", client?"client":"server");
        conn_key_print(key);
        CT_LOG("len = %d\n", len - hlen);
    }
    tcp_statm(th, conn, client);
}

