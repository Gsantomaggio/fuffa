#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("xdp")
int xdp_tcp_filter(struct xdp_md *ctx)
{
    bpf_printk("xdp\n");
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

