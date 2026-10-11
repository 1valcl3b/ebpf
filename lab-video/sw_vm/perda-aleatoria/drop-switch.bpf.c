#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

#define DEST_PORT 5004

// IP de destino: 10.0.0.2.
// Representação utilizada em máquinas x86 com BCC.
#define DEST_IP 0x0200000A

// Índices dos contadores consultados pelo Python.
#define STAT_UDP       0
#define STAT_IDR       1
#define STAT_DROPPED   2
#define STAT_PASSED    3
#define STAT_NON_IDR   4

#define STAT_COUNT     5

// Configuração da porcentagem de perda.
BPF_ARRAY(loss_config, __u32, 1);

// Contadores de pacotes.
BPF_ARRAY(stats, __u64, STAT_COUNT);


int ebpf_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --------------------------------------------------------
    // 1. Cabeçalho Ethernet
    // --------------------------------------------------------

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Processa somente IPv4.
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // --------------------------------------------------------
    // 2. Cabeçalho IPv4
    // --------------------------------------------------------

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Esta implementação considera cabeçalho IPv4 de 20 bytes,
    // sem opções. Pacotes com opções são encaminhados normalmente.
    if (ip->ihl != 5)
        return XDP_PASS;

    if (ip->version != 4)
        return XDP_PASS;

    // Processa somente UDP.
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Filtra o endereço IP de destino.
    if (ip->daddr != DEST_IP)
        return XDP_PASS;

    // --------------------------------------------------------
    // 3. Cabeçalho UDP
    // --------------------------------------------------------

    struct udphdr *udp = (struct udphdr *)(ip + 1);

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Filtra a porta UDP de destino 5004.
    if (udp->dest != htons(DEST_PORT))
        return XDP_PASS;

    // Conta os pacotes UDP que correspondem ao filtro.
    __u32 chave_udp = STAT_UDP;
    __u64 *contador_udp = stats.lookup(&chave_udp);

    if (contador_udp)
        (*contador_udp)++;

    // --------------------------------------------------------
    // 4. Cabeçalho RTP
    // --------------------------------------------------------

    // Cabeçalho RTP básico: 12 bytes.
    // Esta versão assume que não há CSRC nem extensão RTP.

    __u8 *rtp = (__u8 *)(udp + 1);

    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;

    // A versão RTP deve ser 2.
    if ((rtp[0] >> 6) != 2)
        return XDP_PASS;

    // Início do payload H.264.
    __u8 *payload = rtp + 12;

    // Precisamos de dois bytes para identificar também FU-A.
    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;

    // --------------------------------------------------------
    // 5. Identificação do tipo de NAL H.264
    // --------------------------------------------------------

    // Os cinco bits inferiores indicam o tipo de NAL.
    __u8 nal_type = payload[0] & 0x1F;

    int pacote_idr = 0;
    int pacote_non_idr = 0;

    // NAL type 5: IDR.
    if (nal_type == 5) {
        pacote_idr = 1;
    }

    // NAL type 28: FU-A, usado para fragmentar uma NAL.
    // O tipo original da NAL está nos cinco bits inferiores
    // do segundo byte do cabeçalho FU-A.
    else if (nal_type == 28) {

        __u8 tipo_original = payload[1] & 0x1F;

        if (tipo_original == 5) {
            pacote_idr = 1;
        }
        else if (tipo_original == 1) {
            pacote_non_idr = 1;
        }
    }

    // NAL type 1: Non-IDR.
    else if (nal_type == 1) {
        pacote_non_idr = 1;
    }

    // Outros tipos de NAL são encaminhados sem perda aplicada.
    else {
        return XDP_PASS;
    }

    // --------------------------------------------------------
    // 6. Pacotes IDR: perda aleatória configurável
    // --------------------------------------------------------

    if (pacote_idr) {

        __u32 chave_idr = STAT_IDR;
        __u64 *contador_idr = stats.lookup(&chave_idr);

        if (contador_idr)
            (*contador_idr)++;

        // Lê a porcentagem configurada pelo programa Python.
        __u32 indice_config = 0;
        __u32 *config = loss_config.lookup(&indice_config);

        __u32 percentual = 0;

        if (config)
            percentual = *config;

        // Evita valores inválidos acima de 100%.
        if (percentual > 100)
            percentual = 100;

        // Sorteio de 0 a 99 para decidir se descarta o pacote.
        __u32 sorteio = bpf_get_prandom_u32() % 100;

        if (sorteio < percentual) {

            __u32 chave_drop = STAT_DROPPED;
            __u64 *contador_drop = stats.lookup(&chave_drop);

            if (contador_drop)
                (*contador_drop)++;

            return XDP_DROP;
        }

        // O pacote IDR não foi sorteado para descarte.
        __u32 chave_pass = STAT_PASSED;
        __u64 *contador_pass = stats.lookup(&chave_pass);

        if (contador_pass)
            (*contador_pass)++;

        return XDP_PASS;
    }

    // --------------------------------------------------------
    // 7. Pacotes Non-IDR: encaminhamento normal
    // --------------------------------------------------------

    if (pacote_non_idr) {

        __u32 chave_non_idr = STAT_NON_IDR;
        __u64 *contador_non_idr = stats.lookup(&chave_non_idr);

        if (contador_non_idr)
            (*contador_non_idr)++;

        return XDP_PASS;
    }

    return XDP_PASS;
}
