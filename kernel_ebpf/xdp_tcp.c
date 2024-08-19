#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>





#define IPPROTO_TCP  6
#define ETH_P_IP  0x0800

//#define REDIRECT_IP 0xC0A801BD // 192.168.1.189 in network byte order
#define REDIRECT_IP 0x7F000001 // 192.168.1.189 in network byte order
#define REDIRECT_PORT 5552     // Port to redirect to (in host byte order)
#define ORIGINAL_PORT 5553


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} port_filter SEC(".maps");


static __inline __u16 csum_fold_helper(__u32 csum) {
    // Fold the 32-bit checksum into 16 bits and add any carry bits
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

// llvm-objdump -S bpf_func.o
SEC("xdp")
int xdp_tcp_redirect(struct xdp_md *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;

    struct ethhdr *eth = data;
    if ((void *) (eth + 1) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *) (iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *) (tcp + 1) > data_end) {
        return XDP_PASS;
    }

    u32 key = 0;
    u64 *value;
    value = bpf_map_lookup_elem(&port_filter, &key);

    if (value == NULL) {
        bpf_printk("[EBPF Kernel Space VALUE]  value is NULL \n");
    } else {
//        bpf_printk("[EBPF Kernel Space VALUE]  value: %lld ", *value );

//        bpf_printk("bpf_htons(tcp->dest): %d - proto: %d - ETH_P_IP: %d  \n", bpf_htons(tcp->dest), eth->h_proto, ETH_P_IP);
//        if (bpf_htons(tcp->dest) == 22) {
//            return XDP_PASS;
//        }
//        if (bpf_htons(tcp->dest) != *value) {
//            return XDP_PASS;
//        }


        if (tcp->dest == bpf_htons(REDIRECT_PORT)) {
            // Redirect to the new port
            tcp->dest = bpf_htons(REDIRECT_PORT);
            // Recalculate TCP checksum
            __u32 before = tcp->check;
            tcp->check = 0;
            unsigned long long csum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), 0);
            tcp->check = csum_fold_helper(csum);
            bpf_printk("from:  %d - to: %d - before_cs %d, after_cs %d  \n",
                       bpf_htons(ORIGINAL_PORT), bpf_htons(tcp->dest), before, tcp->check);

            return XDP_TX; // Transmit the modified packet
        }



        // Calculate the total length of the packet
//        __u64 packet_len = ctx->data_end - ctx->data;

        // Calculate the length of the TCP header
//        __u32 tcp_header_len = tcp->doff * 4;

        // Calculate the length of the payload
//        __u32 payload_len = packet_len - sizeof(struct ethhdr) - sizeof(struct iphdr) - tcp_header_len;

        // Ensure that we have at least 4 bytes in the payload
//        if (payload_len < 4) {
//            return XDP_PASS;
//        }

        // Modify destination IP address
//        bpf_printk("before ip->daddr %d - REDIRECT_IP: %d - ETH_P_IP: %d  \n", ip->daddr, bpf_htonl(REDIRECT_IP), ETH_P_IP);
//        ip->daddr = bpf_htonl(REDIRECT_IP);
//        bpf_printk("after ip->daddr %d - REDIRECT_IP: %d - ETH_P_IP: %d  \n", ip->daddr, bpf_htonl(REDIRECT_IP), ETH_P_IP);

//        bpf_printk("before tcp->dest %d - REDIRECT_IP: %d - ETH_P_IP: %d  \n", tcp->dest, bpf_htonl(REDIRECT_IP), ETH_P_IP);
        // Modify destination port
//        tcp->dest = bpf_htons(REDIRECT_PORT);
//        ip->check = 0;
//        ip->check = csum_fold_helper(bpf_csum_diff(0, 0, (void *)&ip->daddr, 4, 0));

//        // Recalculate TCP checksum
//        tcp->check = 0;
//        __u32 tcp_csum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), 0);
//        tcp->check = csum_fold_helper(tcp_csum);

//        bpf_printk("after tcp->dest %d - REDIRECT_IP: %d - ETH_P_IP: %d  \n", tcp->dest, bpf_htonl(REDIRECT_IP), ETH_P_IP);
        return XDP_PASS;


//        // Get a pointer to the start of the payload
//        __u8 *payload = (__u8 *) tcp + tcp_header_len;
//        bpf_printk("[EBPF Kernel Space]  full payload  %s \n", payload);
//
//        unsigned char formatBuff[4];
//        if (bpf_probe_read_kernel(&formatBuff, 4, payload) == 0)
//        {
//            bpf_printk("[EBPF Kernel Space] First four bytes: %s \n", formatBuff);
//            return XDP_DROP;
//
//        }
    }

    return XDP_PASS;
}


char _license[]
SEC("license") = "GPL";

