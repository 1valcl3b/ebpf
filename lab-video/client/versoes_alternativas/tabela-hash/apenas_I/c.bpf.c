#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>


#define DEST_PORT 5004


// ============================================================
// Estrutura que representa um pacote I
// ============================================================

struct packet_info
{
    // IPs
    __u32 src_ip;
    __u32 dst_ip;

    // Portas
    __u16 src_port;
    __u16 dst_port;

    // H.264
    __u8 nal_type;

    // FU-A
    __u8 fu_start;
    __u8 fu_end;
};


// ============================================================
// MAPA PRINCIPAL
//
// Uma entrada para cada pacote I.
//
// chave:
//     número sequencial do pacote I
//
// valor:
//     informações do pacote
// ============================================================

BPF_HASH(
    pacotes_i,
    __u32,
    struct packet_info
);


// ============================================================
// MAPA PARA O CONTADOR
//
// chave 0:
//     contador dos pacotes I
//
// valor:
//     número do pacote I
// ============================================================

BPF_ARRAY(
    contador_i,
    __u32,
    1
);


// ============================================================
// PROGRAMA XDP
// ============================================================

int ebpf_xdp(struct xdp_md *ctx)
{
    void *data_end =
        (void *)(long)ctx->data_end;

    void *data =
        (void *)(long)ctx->data;


    // ========================================================
    // ETHERNET
    // ========================================================

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;


    if (eth->h_proto !=
        __constant_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }


    // ========================================================
    // IPv4
    // ========================================================

    struct iphdr *ip =
        (struct iphdr *)(eth + 1);


    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;


    // --------------------------------------------------------
    // Destino: 10.0.0.2
    // --------------------------------------------------------

    if (ip->daddr !=
        __constant_htonl(0x0A000002))
    {
        return XDP_PASS;
    }


    // --------------------------------------------------------
    // Tamanho do cabeçalho IPv4
    // --------------------------------------------------------

    __u32 ip_hdr_len =
        ip->ihl * 4;


    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;


    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;


    // --------------------------------------------------------
    // Verifica se é UDP
    // --------------------------------------------------------

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;


    // ========================================================
    // UDP
    // ========================================================

    struct udphdr *udp =
        (void *)ip + ip_hdr_len;


    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;


    // --------------------------------------------------------
    // Porta destino
    // --------------------------------------------------------

    if (udp->dest !=
        __constant_htons(DEST_PORT))
    {
        return XDP_PASS;
    }


    // ========================================================
    // RTP
    // ========================================================

    __u8 *rtp =
        (__u8 *)(udp + 1);


    // Cabeçalho RTP básico = 12 bytes

    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;


    // --------------------------------------------------------
    // Versão RTP
    // --------------------------------------------------------

    __u8 version =
        (rtp[0] >> 6) & 0x03;


    if (version != 2)
        return XDP_PASS;


    // ========================================================
    // PAYLOAD RTP
    // ========================================================

    __u8 *payload =
        rtp + 12;


    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;


    // ========================================================
    // H.264
    // ========================================================

    __u8 nal_type =
        payload[0] & 0x1F;


    __u8 tipo_h264 =
        nal_type;


    __u8 fu_start = 0;

    __u8 fu_end = 0;


    // ========================================================
    // NAL TYPE 5
    //
    // IDR / I-frame
    // ========================================================

    if (nal_type == 5)
    {
        tipo_h264 = 5;
    }


    // ========================================================
    // FU-A
    //
    // NAL type 28
    // ========================================================

    else if (nal_type == 28)
    {
        __u8 fu_header =
            payload[1];


        __u8 original_nal_type =
            fu_header & 0x1F;


        // ----------------------------------------------------
        // Só queremos FU-A de IDR
        // ----------------------------------------------------

        if (original_nal_type != 5)
            return XDP_PASS;


        // ----------------------------------------------------
        // Start bit
        // ----------------------------------------------------

        fu_start =
            (fu_header >> 7) & 0x01;


        // ----------------------------------------------------
        // End bit
        // ----------------------------------------------------

        fu_end =
            (fu_header >> 6) & 0x01;


        tipo_h264 = 5;
    }


    // ========================================================
    // OUTROS TIPOS H.264
    // ========================================================

    else
    {
        return XDP_PASS;
    }


    // ========================================================
    // CONTADOR DOS PACOTES I
    // ========================================================

    __u32 indice = 0;

    __u32 *contador;


    contador =
        contador_i.lookup(&indice);


    if (!contador)
        return XDP_PASS;


    // --------------------------------------------------------
    // Incrementa o contador
    // --------------------------------------------------------

    (*contador)++;


    __u32 chave =
        *contador;


    // ========================================================
    // MONTA INFORMAÇÕES DO PACOTE
    // ========================================================

    struct packet_info info = {};


    // --------------------------------------------------------
    // IPs
    // --------------------------------------------------------

    info.src_ip =
        ip->saddr;

    info.dst_ip =
        ip->daddr;


    // --------------------------------------------------------
    // Portas
    // --------------------------------------------------------

    info.src_port =
        udp->source;

    info.dst_port =
        udp->dest;


    // --------------------------------------------------------
    // H.264
    // --------------------------------------------------------

    info.nal_type =
        tipo_h264;


    info.fu_start =
        fu_start;


    info.fu_end =
        fu_end;


    // ========================================================
    // INSERE NO HASH
    //
    // chave = ordem do pacote I
    // valor = informações do pacote
    // ========================================================

    pacotes_i.update(
        &chave,
        &info
    );


    return XDP_PASS;
}