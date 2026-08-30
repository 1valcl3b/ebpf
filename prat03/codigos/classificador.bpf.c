#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

#define DEST_PORT 5004


int ebpf_xdp(struct xdp_md *ctx)
{
    // =========================================================
    // LIMITES DO PACOTE
    // =========================================================

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;


    // =========================================================
    // ETHERNET
    // =========================================================

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    bpf_trace_printk("Passei pelo Ethernet\n");

    // Apenas IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;


    // =========================================================
    // IPv4
    // =========================================================

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    bpf_trace_printk("Passei pelo IPv4\n");


    // Apenas destino 10.0.0.2
    if (ip->daddr != __constant_htonl(0x0A000002))
        return XDP_PASS;

    bpf_trace_printk("IP de destino = 10.0.0.2\n");

    // Calcula tamanho do cabeçalho IP
    __u32 ip_hdr_len = ip->ihl * 4;

    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;


    // =========================================================
    // UDP
    // =========================================================

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;


    struct udphdr *udp = (void *)ip + ip_hdr_len;

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    bpf_trace_printk("Passei pelo UDP\n");


    // Apenas porta 5004
    if (udp->dest != __constant_htons(DEST_PORT))
        return XDP_PASS;

    bpf_trace_printk("Pacote UDP com porta dedestino 5004\n");

    // =========================================================
    // RTP
    // =========================================================

    __u8 *rtp = (__u8 *)(udp + 1);

    // RTP mínimo = 12 bytes
    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;


    // RTP versão
    __u8 version = (rtp[0] >> 6) & 0x03;

    if (version != 2)
        return XDP_PASS;

    bpf_trace_printk("Passei pelo RTP HEADER\n");

    // =========================================================
    // RTP PAYLOAD
    // =========================================================

    __u8 *payload = rtp + 12;

    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;

    bpf_trace_printk("Passei pelo RTP PAYLOAD\n");
    // =========================================================
    // H.264 NAL TYPE
    // =========================================================

    __u8 nal_type = payload[0] & 0x1F;


    // =========================================================
    // NAL NÃO FRAGMENTADO
    // =========================================================

    if (nal_type == 5)
    {
        // IDR
        bpf_trace_printk("pacote IDR\n");
    }

    else if (nal_type == 1)
    {
        // Non-IDR
        bpf_trace_printk("pacote Non-IDR\n");
    }


    // =========================================================
    // FU-A
    // =========================================================

    else if (nal_type == 28)
    {
        /*
         * FU-A:
         *
         * payload[0] = FU Indicator
         * payload[1] = FU Header
         */

        __u8 fu_header = payload[1];


        // Tipo NAL original
        __u8 original_nal_type = fu_header & 0x1F;


        // -----------------------------------------------------
        // IDR fragmentado
        // -----------------------------------------------------

        if (original_nal_type == 5)
        {
            bpf_trace_printk("pacote IDR\n");
        }


        // -----------------------------------------------------
        // Non-IDR fragmentado
        // -----------------------------------------------------

        else if (original_nal_type == 1)
        {
            bpf_trace_printk("pacote Non-IDR\n");
        }
    }


    // =========================================================
    // NÃO MODIFICA O PACOTE
    // =========================================================

    return XDP_PASS;
}