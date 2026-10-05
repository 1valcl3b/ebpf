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
    // Tipo do pacote
    // 0 = I
    // 1 = Non-I
    __u8 tipo;

    // IPs
    __u32 src_ip;
    __u32 dst_ip;

    // Portas
    __u16 src_port;
    __u16 dst_port;

    // RTP
    __u16 rtp_seq;
    __u32 rtp_timestamp;
    __u8 rtp_marker;

    // H.264
    __u8 nal_type;

    // FU-A
    __u8 fu_start;
    __u8 fu_end;

    // Timestamp do kernel
    __u64 timestamp_ns;
};


// ============================================================
// MAPA eBPF
//
// Uma única tabela contendo TODOS os pacotes H.264
// classificados como I ou Non-I.
//
// Chave:
//     número sequencial do pacote
//
// Valor:
//     informações do pacote
// ============================================================

BPF_HASH(
    pacotes,
    __u64,
    struct packet_info,
    20000
);


// ============================================================
// CONTADOR
//
// índice 0:
//     contador global dos pacotes
// ============================================================

BPF_ARRAY(contador, __u64, 1);


// ============================================================
// PROGRAMA XDP
// ============================================================

int ebpf_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;


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


    // --------------------------------------------------------
    // Destino: 10.0.0.2
    // --------------------------------------------------------

    if (ip->daddr != __constant_htonl(0x0A000002))
        return XDP_PASS;


    // --------------------------------------------------------
    // Tamanho do cabeçalho IPv4
    // --------------------------------------------------------

    __u32 ip_hdr_len = ip->ihl * 4;

    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;


    // --------------------------------------------------------
    // Verifica UDP
    // --------------------------------------------------------

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;


    // ========================================================
    // UDP
    // ========================================================

    struct udphdr *udp = (void *)ip + ip_hdr_len;

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;


    // --------------------------------------------------------
    // Porta destino
    // --------------------------------------------------------

    if (udp->dest != __constant_htons(DEST_PORT))
        return XDP_PASS;


    // ========================================================
    // RTP
    // ========================================================

    __u8 *rtp = (__u8 *)(udp + 1);

    // Cabeçalho RTP básico = 12 bytes

    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;


    // --------------------------------------------------------
    // Versão RTP
    // --------------------------------------------------------

    __u8 version = (rtp[0] >> 6) & 0x03;

    if (version != 2)
        return XDP_PASS;


    // ========================================================
    // PAYLOAD RTP
    // ========================================================

    __u8 *payload = rtp + 12;

    // Precisamos de pelo menos 2 bytes para analisar
    // NAL e, caso seja FU-A, o FU header.

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


    // ========================================================
    // NAL TYPE 5
    //
    // IDR / I
    // ========================================================

    if (nal_type == 5)
    {
        tipo = TIPO_I;

        tipo_h264 = 5;
    }


    // ========================================================
    // NAL TYPE 1
    //
    // Non-IDR / Non-I
    // ========================================================

    else if (nal_type == 1)
    {
        tipo = TIPO_NON_I;

        tipo_h264 = 1;
    }


    // ========================================================
    // FU-A
    //
    // NAL type 28
    // ========================================================

    else if (nal_type == 28)
    {
        // Segundo byte do FU-A
        __u8 fu_header = payload[1];

        // Recupera o tipo NAL original
        __u8 original_nal_type = fu_header & 0x1F;


        // ----------------------------------------------------
        // Start bit
        // ----------------------------------------------------

        fu_start = (fu_header >> 7) & 0x01;


        // ----------------------------------------------------
        // End bit
        // ----------------------------------------------------

        fu_end = (fu_header >> 6) & 0x01;


        // ----------------------------------------------------
        // FU-A de IDR
        // ----------------------------------------------------

        if (original_nal_type == 5)
        {
            tipo = TIPO_I;

            tipo_h264 = 5;
        }


        // ----------------------------------------------------
        // FU-A de Non-IDR
        // ----------------------------------------------------

        else if (original_nal_type == 1)
        {
            tipo = TIPO_NON_I;

            tipo_h264 = 1;
        }


        // ----------------------------------------------------
        // Outros tipos
        // ----------------------------------------------------

        else
        {
            return XDP_PASS;
        }
    }


    // ========================================================
    // OUTROS TIPOS H.264
    // ========================================================

    else
    {
        return XDP_PASS;
    }


    // ========================================================
    // OBTÉM O CONTADOR
    // ========================================================

    __u32 indice = 0;

    __u64 *contador_ptr;

    contador_ptr = contador.lookup(&indice);

    if (!contador_ptr)
        return XDP_PASS;


    // ========================================================
    // GERA A ORDEM DO PACOTE
    //
    // Primeiro pacote:
    //     1
    //
    // Segundo pacote:
    //     2
    //
    // Terceiro pacote:
    //     3
    // ========================================================

    __u64 chave;

    chave = *contador_ptr + 1;

    *contador_ptr = chave;


    // ========================================================
    // PREENCHE OS DADOS DO PACOTE
    // ========================================================

    struct packet_info info = {};


    // --------------------------------------------------------
    // Tipo
    // --------------------------------------------------------

    info.tipo = tipo;


    // --------------------------------------------------------
    // IP
    // --------------------------------------------------------

    info.src_ip = ip->saddr;

    info.dst_ip = ip->daddr;


    // --------------------------------------------------------
    // Portas
    // --------------------------------------------------------

    info.src_port = udp->source;

    info.dst_port = udp->dest;


    // ========================================================
    // RTP SEQUENCE
    // ========================================================

    info.rtp_seq =
        ((__u16)rtp[2] << 8) |
        ((__u16)rtp[3]);


    // ========================================================
    // RTP TIMESTAMP
    // ========================================================

    info.rtp_timestamp =
        ((__u32)rtp[4] << 24) |
        ((__u32)rtp[5] << 16) |
        ((__u32)rtp[6] << 8) |
        ((__u32)rtp[7]);


    // ========================================================
    // RTP MARKER
    // ========================================================

    info.rtp_marker =
        (rtp[1] >> 7) & 0x01;


    // ========================================================
    // H.264
    // ========================================================

    info.nal_type = tipo_h264;

    info.fu_start = fu_start;

    info.fu_end = fu_end;


    // ========================================================
    // TIMESTAMP DO KERNEL
    // ========================================================

    info.timestamp_ns =
        bpf_ktime_get_ns();


    // ========================================================
    // INSERE NO MAPA
    //
    // chave:
    //     número sequencial do pacote
    //
    // valor:
    //     informações do pacote
    // ========================================================

    pacotes.update(
        &chave,
        &info
    );


    // ========================================================
    // NÃO DESCARTA O PACOTE
    // ========================================================

    return XDP_PASS;
}