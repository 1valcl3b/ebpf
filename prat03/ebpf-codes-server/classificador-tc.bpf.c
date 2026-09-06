#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

#include <linux/in.h>
#include <linux/pkt_cls.h>

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
// quantidade de pacotes enviados
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

        packet_count.update(&key, &inicial);
    }
}


// =========================================================
// TC PROGRAM
// =========================================================

int ebpf_tc(struct __sk_buff *skb)
{
    // =========================================================
    // LIMITES DO PACOTE
    // =========================================================

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;


    // =========================================================
    // ETHERNET
    // =========================================================

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;


    // Apenas IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;


    // =========================================================
    // IPv4
    // =========================================================

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;


    // Apenas destino 10.0.0.2
    if (ip->daddr != __constant_htonl(0x0A000002))
        return TC_ACT_OK;


    // Tamanho do cabeçalho IPv4
    __u32 ip_hdr_len = ip->ihl * 4;


    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;


    if ((void *)ip + ip_hdr_len > data_end)
        return TC_ACT_OK;


    // =========================================================
    // UDP
    // =========================================================

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;


    struct udphdr *udp =
        (void *)ip + ip_hdr_len;


    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;


    // Apenas porta destino 5004
    if (udp->dest != __constant_htons(DEST_PORT))
        return TC_ACT_OK;


    // =========================================================
    // RTP
    // =========================================================

    __u8 *rtp =
        (__u8 *)(udp + 1);


    // RTP mínimo = 12 bytes
    if ((void *)(rtp + 12) > data_end)
        return TC_ACT_OK;


    // RTP versão
    __u8 version =
        (rtp[0] >> 6) & 0x03;


    if (version != 2)
        return TC_ACT_OK;


    // =========================================================
    // RTP PAYLOAD
    // =========================================================

    __u8 *payload =
        rtp + 12;


    // Precisamos de pelo menos 2 bytes
    if ((void *)(payload + 2) > data_end)
        return TC_ACT_OK;


    // =========================================================
    // H264 NAL TYPE
    // =========================================================

    __u8 nal_type =
        payload[0] & 0x1F;


    // =========================================================
    // NAL NÃO FRAGMENTADA
    // =========================================================

    if (nal_type == 5)
    {
        incrementar_contador(TYPE_IDR);
    }

    else if (nal_type == 1)
    {
        incrementar_contador(TYPE_NON_IDR);
    }


    // =========================================================
    // FU-A
    // =========================================================

    else if (nal_type == 28)
    {
        /*
         * payload[0] = FU Indicator
         * payload[1] = FU Header
         */

        __u8 fu_header =
            payload[1];


        // Tipo original da NAL
        __u8 original_nal_type =
            fu_header & 0x1F;


        // IDR fragmentado
        if (original_nal_type == 5)
        {
            incrementar_contador(TYPE_IDR);
        }


        // Non-IDR fragmentado
        else if (original_nal_type == 1)
        {
            incrementar_contador(TYPE_NON_IDR);
        }
    }


    // Não modifica o pacote
    return TC_ACT_OK;
}