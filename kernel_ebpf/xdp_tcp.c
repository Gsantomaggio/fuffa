#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>



#define IPPROTO_TCP  6
#define ETH_P_IP  0x0800


struct bpf_map_def SEC(

"maps")
port_filter = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 2,
};

// llvm-objdump -S bpf_func.o
SEC(

"xdp")

int xdp_tcp_filter(struct xdp_md *ctx) {

//    bpf_printk("[EBPF Kernel Space]  start ***** \n");


    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;

    struct ethhdr *eth = data;
    if ((void *) (eth + 1) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *) (ip + 1) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *) (tcp + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 key = 0;
    __u32 *value;
    value = bpf_map_lookup_elem(&port_filter, &key);
    if (value) {
        if (bpf_htons(tcp->dest) == 22) {
            return XDP_PASS;
        }
//              bpf_printk("bpf_htons(tcp->dest): %d - proto: %d - ETH_P_IP: %d  \n", bpf_htons(tcp->dest), eth->h_proto, ETH_P_IP);
        if (bpf_htons(tcp->dest) != *value) {
            return XDP_PASS;
        }



        // Calculate the total length of the packet
        __u64 packet_len = ctx->data_end - ctx->data;

        // Calculate the length of the TCP header
        __u32 tcp_header_len = tcp->doff * 4;

        // Calculate the length of the payload
        __u32 payload_len = packet_len - sizeof(struct ethhdr) - sizeof(struct iphdr) - tcp_header_len;

        // Ensure that we have at least 4 bytes in the payload
        if (payload_len < 4) {
            return XDP_PASS;
        }

        // Get a pointer to the start of the payload
        __u8 *payload = (__u8 *) tcp + tcp_header_len;
        bpf_printk("[EBPF Kernel Space]  full payload  %s \n", payload);

        unsigned char formatBuff[4];
        if (bpf_probe_read_kernel(&formatBuff, 4, payload) == 0)
        {
            bpf_printk("[EBPF Kernel Space] First four bytes: %s \n", formatBuff);
            return XDP_DROP;

        }
    }

    return XDP_PASS;
}


char _license[]
SEC("license") = "GPL";

