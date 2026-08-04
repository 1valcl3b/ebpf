#include <uapi/linux/bpf.h>


int chegou(struct xdp_md *ctx)
{
    bpf_trace_printk("Pacote chegou");

    return XDP_PASS;
}