#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

#define DEST_PORT 5004

#define TYPE_IDR     0
#define TYPE_NON_IDR 1


// =========================================================
// HASH TABLE
//
// Key:
// 0 = IDR
// 1 = Non-IDR
//
// Value:
// quantidade de pacotes
// =========================================================

BPF_HASH(packet_count, __u32, __u64);


// =========================================================
// FUNÇÃO PARA INCREMENTAR CONTADOR
// =========================================================

static __always_inline void incrementar_contador(__u32 key)
{
    __u64 *valor;

    valor = packet_count.lookup(&key);

    if (valor)
    {
        __sync_fetch_and_add(valor, 1);
    }
    else
    {
        __u64 inicial = 1;

        packet_count.update(
            &key,
            &inicial
        );
    }
}


// =========================================================
// XDP PROGRAM
// =========================================================

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

    // Apenas IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;


    // =========================================================
    // IPv4
    // =========================================================

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;


    // Apenas destino 10.0.0.2
    if (ip->daddr != __constant_htonl(0x0A000002))
        return XDP_PASS;


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


    // Apenas porta 5004
    if (udp->dest != __constant_htons(DEST_PORT))
        return XDP_PASS;


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


    // =========================================================
    // RTP PAYLOAD
    // =========================================================

    __u8 *payload = rtp + 12;


    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;


    // =========================================================
    // H264 NAL TYPE
    // =========================================================

    __u8 nal_type = payload[0] & 0x1F;


    // =========================================================
    // NAL NÃO FRAGMENTADO
    // =========================================================

    if (nal_type == 5)
    {
        // IDR

        incrementar_contador(TYPE_IDR);

        bpf_trace_printk("pacote IDR\n");
    }

    else if (nal_type == 1)
    {
        // Non-IDR

        incrementar_contador(TYPE_NON_IDR);

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
            incrementar_contador(TYPE_IDR);

            bpf_trace_printk("pacote IDR\n");
        }


        // -----------------------------------------------------
        // Non-IDR fragmentado
        // -----------------------------------------------------

        else if (original_nal_type == 1)
        {
            incrementar_contador(TYPE_NON_IDR);

            bpf_trace_printk("pacote Non-IDR\n");
        }
    }


    return XDP_PASS;
}