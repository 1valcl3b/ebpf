#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>


// =========================================================
// CONFIGURAÇÃO
// =========================================================

#define DEST_PORT 5004

#define TYPE_IDR     0
#define TYPE_NON_IDR 1


// =========================================================
// ESTRUTURA DO EVENTO
//
// Cada pacote identificado pelo XDP gera um evento.
// O Python recebe esse evento e grava uma linha no CSV.
// =========================================================

struct packet_event
{
    // Tipo identificado
    // 0 = IDR
    // 1 = Non-IDR
    __u32 type;

    // Informações IP
    __u32 src_ip;
    __u32 dst_ip;

    // Portas UDP
    __u16 src_port;
    __u16 dst_port;

    // Informações RTP
    __u16 rtp_seq;
    __u32 rtp_timestamp;
    __u8  rtp_marker;

    // Informações H.264
    __u8 nal_type;

    // Informações específicas de FU-A
    __u8 fu_start;
    __u8 fu_end;

    // Timestamp gerado pelo kernel
    __u64 timestamp_ns;
};


// =========================================================
// PERF OUTPUT
//
// O XDP envia cada pacote identificado para o Python.
// =========================================================

BPF_PERF_OUTPUT(events);


// =========================================================
// XDP PROGRAM
// =========================================================

int ebpf_xdp(struct xdp_md *ctx)
{
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


    // Tamanho do cabeçalho IP
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


    // Apenas porta UDP 5004
    if (udp->dest != __constant_htons(DEST_PORT))
        return XDP_PASS;


    // =========================================================
    // RTP
    // =========================================================

    __u8 *rtp = (__u8 *)(udp + 1);


    // Cabeçalho RTP mínimo = 12 bytes
    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;


    // Versão RTP
    __u8 version = (rtp[0] >> 6) & 0x03;

    if (version != 2)
        return XDP_PASS;


    // =========================================================
    // PAYLOAD RTP
    // =========================================================

    __u8 *payload = rtp + 12;

    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;


    // =========================================================
    // IDENTIFICAÇÃO H.264
    // =========================================================

    __u8 nal_type = payload[0] & 0x1F;

    __u32 tipo_pacote = 0;

    __u8 fu_start = 0;
    __u8 fu_end = 0;
    __u8 tipo_h264 = nal_type;


    // ---------------------------------------------------------
    // NAL UNIT TYPE 5
    //
    // IDR
    // ---------------------------------------------------------

    if (nal_type == 5)
    {
        tipo_pacote = TYPE_IDR;
    }


    // ---------------------------------------------------------
    // NAL UNIT TYPE 1
    //
    // Non-IDR
    // ---------------------------------------------------------

    else if (nal_type == 1)
    {
        tipo_pacote = TYPE_NON_IDR;
    }


    // ---------------------------------------------------------
    // NAL UNIT TYPE 28
    //
    // FU-A
    // ---------------------------------------------------------

    else if (nal_type == 28)
    {
        __u8 fu_header = payload[1];

        // Tipo original do NAL
        __u8 original_nal_type = fu_header & 0x1F;

        // Bit Start
        fu_start = (fu_header >> 7) & 0x01;

        // Bit End
        fu_end = (fu_header >> 6) & 0x01;

        tipo_h264 = original_nal_type;


        // FU-A de IDR
        if (original_nal_type == 5)
        {
            tipo_pacote = TYPE_IDR;
        }


        // FU-A de Non-IDR
        else if (original_nal_type == 1)
        {
            tipo_pacote = TYPE_NON_IDR;
        }


        // Outros tipos H.264
        else
        {
            return XDP_PASS;
        }
    }


    // ---------------------------------------------------------
    // Outros tipos H.264
    // ---------------------------------------------------------

    else
    {
        return XDP_PASS;
    }


    // =========================================================
    // CRIA EVENTO
    // =========================================================

    struct packet_event event = {};

    event.type = tipo_pacote;

    // Informações IP
    event.src_ip = ip->saddr;
    event.dst_ip = ip->daddr;

    // Portas
    event.src_port = udp->source;
    event.dst_port = udp->dest;

    // RTP Sequence Number
    event.rtp_seq =
        ((__u16)rtp[2] << 8) |
        ((__u16)rtp[3]);

    // RTP Timestamp
    event.rtp_timestamp =
        ((__u32)rtp[4] << 24) |
        ((__u32)rtp[5] << 16) |
        ((__u32)rtp[6] << 8)  |
        ((__u32)rtp[7]);

    // Marker bit
    event.rtp_marker = (rtp[1] >> 7) & 0x01;

    // Tipo H.264 original
    event.nal_type = tipo_h264;

    // FU-A
    event.fu_start = fu_start;
    event.fu_end = fu_end;

    // Timestamp do kernel
    event.timestamp_ns = bpf_ktime_get_ns();


    // =========================================================
    // ENVIA EVENTO PARA O PYTHON
    // =========================================================

    events.perf_submit(
        ctx,
        &event,
        sizeof(event)
    );


    return XDP_PASS;
}

