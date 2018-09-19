#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "tool.h"
#include "proto.h"
#include "log.h"

static void loop_callback(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet);
int
ct_decrypt_file(const char *output, const char *input, const char *key,
            const char *random, const char *filter_str)
{
    pcap_t              *handle = NULL;
    struct bpf_program  filter = {};
    char                errbuf[PCAP_ERRBUF_SIZE] = {};

    handle = pcap_open_offline(input, errbuf);
    if (handle == NULL) {
        CT_LOG("Open file %s failed(%s)\n", input, errbuf);
        return -1;
    }

    if (filter_str != NULL) {
        pcap_compile(handle, &filter, filter_str, 1, 0);
        if (pcap_setfilter(handle, &filter) != 0) {
            CT_LOG("Set filter %s failed(%s)\n", filter_str, errbuf);
            pcap_close(handle);
            return -1;
        }
    } 

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

    eth = (void *)packet;
    type = ntohs(eth->ether_type);
    handler = proto_find_handler(type);
    count++;
    fprintf(stdout, "count = %d\n", count);
    if (handler == NULL) {
        fprintf(stdout, "No handler for eth type = %x\n", type);
        return;
    }

    handler(eth + 1);
}
