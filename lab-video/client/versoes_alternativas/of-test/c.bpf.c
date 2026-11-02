
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

#define DEST_PORT 5004

#define TIPO_I      0
#define TIPO_NON_I  1

// ============================================================
// Estrutura que representa um pacote H.264
// ============================================================

struct packet_info
{
    __u8 tipo;

    __u32 src_ip;
    __u32 dst_ip;

    __u16 src_port;
    __u16 dst_port;

    __u16 rtp_seq;
    __u32 rtp_timestamp;
    __u8 rtp_marker;

    __u8 nal_type;

    __u8 fu_start;
    __u8 fu_end;

    __u64 timestamp_ns;
};

// ============================================================
// MAPA: informações dos pacotes
// ============================================================

BPF_HASH(
    pacotes,
    __u64,
    struct packet_info,
    20000
);

// ============================================================
// CONTADOR: ordem dos pacotes
// ============================================================

BPF_ARRAY(contador, __u64, 1);

// ============================================================
// PROGRAMA XDP
// ============================================================

int ebpf_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ========================================================
    // ETHERNET
    // ========================================================

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // ========================================================
    // IPv4
    // ========================================================

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->version != 4)
        return XDP_PASS;

    // Destino: 10.0.0.2

    if (ip->daddr != __constant_htonl(0x0A000002))
        return XDP_PASS;

    // Verifica se o cabeçalho IPv4 está completo.

    __u32 ip_hdr_len = ip->ihl * 4;

    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Não processa fragmentos IPv4.
    // Isso evita interpretar fragmentos como datagramas UDP completos.

    if (ip->frag_off & __constant_htons(0x1FFF))
        return XDP_PASS;

    // ========================================================
    // UDP
    // ========================================================

    struct udphdr *udp = (void *)ip + ip_hdr_len;

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != __constant_htons(DEST_PORT))
        return XDP_PASS;

    // ========================================================
    // RTP: cabeçalho básico de 12 bytes
    // ========================================================

    __u8 *rtp = (__u8 *)(udp + 1);

    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;

    // Versão RTP deve ser 2.

    __u8 version = (rtp[0] >> 6) & 0x03;

    if (version != 2)
        return XDP_PASS;

    // Este código considera somente o cabeçalho RTP básico.
    // CSRCs e extensões RTP não são interpretados.

    __u8 csrc_count = rtp[0] & 0x0F;
    __u8 extension = (rtp[0] >> 4) & 0x01;

    if (csrc_count != 0 || extension != 0)
        return XDP_PASS;

    // ========================================================
    // PAYLOAD RTP
    // ========================================================

    __u8 *payload = rtp + 12;

    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;

    // ========================================================
    // H.264
    // ========================================================

    __u8 nal_type = payload[0] & 0x1F;

    __u8 tipo;
    __u8 tipo_h264 = nal_type;

    __u8 fu_start = 0;
    __u8 fu_end = 0;

    // --------------------------------------------------------
    // NAL TYPE 5: IDR / I
    // --------------------------------------------------------

    if (nal_type == 5)
    {
        tipo = TIPO_I;
        tipo_h264 = 5;
    }

    // --------------------------------------------------------
    // NAL TYPE 1: Non-IDR / Non-I
    // --------------------------------------------------------

    else if (nal_type == 1)
    {
        tipo = TIPO_NON_I;
        tipo_h264 = 1;
    }

    // --------------------------------------------------------
    // FU-A: NAL TYPE 28
    // --------------------------------------------------------

    else if (nal_type == 28)
    {
        __u8 fu_header = payload[1];

        __u8 original_nal_type = fu_header & 0x1F;

        fu_start = (fu_header >> 7) & 0x01;
        fu_end = (fu_header >> 6) & 0x01;

        if (original_nal_type == 5)
        {
            tipo = TIPO_I;
            tipo_h264 = 5;
        }
        else if (original_nal_type == 1)
        {
            tipo = TIPO_NON_I;
            tipo_h264 = 1;
        }
        else
        {
            return XDP_PASS;
        }
    }
    else
    {
        return XDP_PASS;
    }

    // ========================================================
    // CONTADOR
    // ========================================================

    __u32 indice = 0;

    __u64 *contador_ptr = contador.lookup(&indice);

    if (!contador_ptr)
        return XDP_PASS;

    // Mantém o mesmo mecanismo de contador do código original.

    __u64 chave = *contador_ptr + 1;

    *contador_ptr = chave;

    // ========================================================
    // PREENCHE OS DADOS
    // ========================================================

    struct packet_info info = {};

    info.tipo = tipo;

    info.src_ip = ip->saddr;
    info.dst_ip = ip->daddr;

    info.src_port = udp->source;
    info.dst_port = udp->dest;

    info.rtp_seq =
        ((__u16)rtp[2] << 8) |
        ((__u16)rtp[3]);

    info.rtp_timestamp =
        ((__u32)rtp[4] << 24) |
        ((__u32)rtp[5] << 16) |
        ((__u32)rtp[6] << 8) |
        ((__u32)rtp[7]);

    info.rtp_marker = (rtp[1] >> 7) & 0x01;

    info.nal_type = tipo_h264;

    info.fu_start = fu_start;
    info.fu_end = fu_end;

    info.timestamp_ns = bpf_ktime_get_ns();

    // ========================================================
    // INSERE NO MAPA
    // ========================================================

    pacotes.update(&chave, &info);

    return XDP_PASS;
}
