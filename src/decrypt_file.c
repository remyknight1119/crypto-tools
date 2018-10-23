#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "tool.h"
#include "proto.h"
#include "log.h"
#include "tcp.h"
#include "ssl.h"
#include "comm.h"

static void loop_callback(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet);
int
ct_decrypt_file(const char *output, const char *input, const char *key,
            const char *random, const char *filter_str)
{
    pcap_t              *handle = NULL;
    struct bpf_program  filter = {};
    char                errbuf[PCAP_ERRBUF_SIZE] = {};
    char                cmd[CT_CMD_BUF_SIZE] = {};
    int                 ret = 0;

    handle = pcap_open_offline(input, errbuf);
    if (handle == NULL) {
        CT_LOG("Open file %s failed(%s)\n", input, errbuf);
        return -1;
    }

    if (filter_str != NULL) {
        if (pcap_compile(handle, &filter, filter_str, 1, 0) != 0) {
            CT_LOG("Pcap compile \"%s\" failed(%s)\n", filter_str, pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }

        if (pcap_setfilter(handle, &filter) != 0) {
            CT_LOG("Set filter \"%s\" failed(%s)\n", filter_str, pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
    } 

    if (ssl_init(key) != 0) {
        CT_LOG("SSL init failed\n");
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "mkdir -p %s", output);
    fprintf(stdout, "%s\n", cmd);
    ret = system(cmd);
    fprintf(stdout, "cmd ret = %d\n", ret);
    decrypt_dir = output;
    pcap_loop(handle, -1, loop_callback, NULL);

    pcap_close(handle);
    return 0;
}

static void
loop_callback(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
    struct ether_header     *eth = NULL;
    proto_handler           handler = NULL;
    uint16_t                type = 0;
    static int count = 0;

    packet_count++;
    eth = (void *)packet;
    type = ntohs(eth->ether_type);
    handler = proto_find_handler(type);
    count++;
    if (handler == NULL) {
        fprintf(stdout, "No handler for eth type = %x\n", type);
        return;
    }

    handler(eth + 1);
}
