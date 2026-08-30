#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>


// =============================================================
// CONFIGURAÇÃO DO FLUXO
// =============================================================

// IP do CLIENTE
#define DEST_IP 0x0200000A
// 10.0.0.2 em ordem de bytes utilizada na comparação abaixo
//
// 10.0.0.2 = 0x0A000002
//
// Como o campo ip->daddr está em network byte order,
// usamos __constant_htonl() na comparação.

#define DEST_PORT 5004


// =============================================================
// FUNÇÃO PRINCIPAL XDP
// =============================================================

int ebpf_xdp(struct xdp_md *ctx)
{
    // =========================================================
    // LIMITES DO PACOTE
    // =========================================================

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;


    // =========================================================
    // 1. ETHERNET
    // =========================================================

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    bpf_trace_printk("ETH OK\n");


    // ---------------------------------------------------------
    // Verifica IPv4
    // ---------------------------------------------------------

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    bpf_trace_printk("IPv4 OK\n");


    // =========================================================
    // 2. IPv4
    // =========================================================

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    bpf_trace_printk("IP HEADER OK\n");


    // ---------------------------------------------------------
    // Verifica IP DESTINO
    // ---------------------------------------------------------

    if (ip->daddr != __constant_htonl(0x0A000002))
        return XDP_PASS;

    bpf_trace_printk("DEST IP = 10.0.0.2\n");


    // =========================================================
    // TAMANHO DO CABEÇALHO IP
    // =========================================================

    __u32 ip_hdr_len = ip->ihl * 4;

    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    bpf_trace_printk(
        "IP HEADER LENGTH = %d\n",
        ip_hdr_len
    );


    // =========================================================
    // 3. UDP
    // =========================================================

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    bpf_trace_printk("UDP PROTOCOL OK\n");


    struct udphdr *udp = (void *)ip + ip_hdr_len;

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    bpf_trace_printk("UDP HEADER OK\n");


    // =========================================================
    // 4. PORTA UDP
    // =========================================================

    __u16 sport = ntohs(udp->source);
    __u16 dport = ntohs(udp->dest);


    bpf_trace_printk(
        "UDP SPORT = %d\n",
        sport
    );

    bpf_trace_printk(
        "UDP DPORT = %d\n",
        dport
    );


    // ---------------------------------------------------------
    // Filtra pela porta de destino
    // ---------------------------------------------------------

    if (udp->dest != __constant_htons(DEST_PORT))
        return XDP_PASS;

    bpf_trace_printk("VIDEO PORT 5004\n");


    // =========================================================
    // 5. RTP
    // =========================================================

    /*
     * RTP possui, no mínimo, 12 bytes de cabeçalho.
     */

    __u8 *rtp = (__u8 *)(udp + 1);

    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;


    // =========================================================
    // 6. RTP VERSION
    // =========================================================

    __u8 rtp_version = (rtp[0] >> 6) & 0x03;


    bpf_trace_printk(
        "RTP VERSION = %d\n",
        rtp_version
    );


    // RTP versão 2
    if (rtp_version != 2)
    {
        bpf_trace_printk(
            "NOT RTP - VERSION = %d\n",
            rtp_version
        );

        return XDP_PASS;
    }

    bpf_trace_printk("RTP HEADER OK\n");


    // =========================================================
    // 7. RTP PAYLOAD
    // =========================================================

    /*
     * RTP básico:
     *
     * 12 bytes de cabeçalho
     *
     * payload começa em:
     *
     * rtp + 12
     */

    __u8 *payload = rtp + 12;


    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;

    bpf_trace_printk("RTP PAYLOAD OK\n");


    // =========================================================
    // 8. DEBUG RTP
    // =========================================================

    // bpf_trace_printk(
    //     "RTP BYTE 0 = %x\n",
    //     rtp[0]
    // );

    // bpf_trace_printk(
    //     "RTP BYTE 1 = %x\n",
    //     rtp[1]
    // );

    // bpf_trace_printk(
    //     "RTP BYTE 2 = %x\n",
    //     rtp[2]
    // );

    // bpf_trace_printk(
    //     "RTP BYTE 3 = %x\n",
    //     rtp[3]
    // );




    __u8 nal_type = payload[0] & 0x1F;


    bpf_trace_printk(
        "H264 NAL TYPE = %d\n",
        nal_type
    );


    // =========================================================
    // 10. IDENTIFICA NAL H.264
    // =========================================================

    /*
     * Tipos importantes:
     *
     * 1  = Coded slice (non-IDR)
     * 5  = IDR
     * 6  = SEI
     * 7  = SPS
     * 8  = PPS
     * 24 = STAP-A
     * 28 = FU-A
     */


    if (nal_type == 5)
    {
        bpf_trace_printk(
            "H264 IDR - NAL TYPE = 5\n"
        );
    }


    else if (nal_type == 1)
    {
        bpf_trace_printk(
            "H264 NON-IDR - NAL TYPE = 1\n"
        );
    }


    else if (nal_type == 7)
    {
        bpf_trace_printk(
            "H264 SPS - NAL TYPE = 7\n"
        );
    }


    else if (nal_type == 8)
    {
        bpf_trace_printk(
            "H264 PPS - NAL TYPE = 8\n"
        );
    }


    // =========================================================
    // 11. FU-A
    // =========================================================

    /*
     * Quando NAL Type = 28:
     *
     * o pacote é um FU-A.
     *
     * Estrutura:
     *
     * RTP payload:
     *
     * +-------------+
     * | FU indicator|  byte 0
     * +-------------+
     * | FU header   |  byte 1
     * +-------------+
     * | Fragment     |
     * +-------------+
     *
     *
     * FU Indicator:
     *
     * F | NRI | Type
     *
     * Type = 28
     *
     *
     * FU Header:
     *
     * +---+---+--------+
     * | S | E |  Type  |
     * +---+---+--------+
     *
     * S = Start
     * E = End
     *
     * Type = NAL original
     */

    if (nal_type == 28)
    {
        bpf_trace_printk("H264 FU-A DETECTED\n");


        // Precisamos de pelo menos dois bytes
        if ((void *)(payload + 2) > data_end)
            return XDP_PASS;


        __u8 fu_header = payload[1];


        bpf_trace_printk(
            "FU HEADER = %x\n",
            fu_header
        );


        // -----------------------------------------------------
        // NAL TYPE ORIGINAL
        // -----------------------------------------------------

        __u8 original_nal_type = fu_header & 0x1F;


        bpf_trace_printk(
            "ORIGINAL NAL TYPE = %d\n",
            original_nal_type
        );


        // -----------------------------------------------------
        // START
        // -----------------------------------------------------

        if (fu_header & 0x80)
        {
            bpf_trace_printk("FU START\n");
        }


        // -----------------------------------------------------
        // END
        // -----------------------------------------------------

        if (fu_header & 0x40)
        {
            bpf_trace_printk("FU END\n");
        }


        // -----------------------------------------------------
        // Classificação
        // -----------------------------------------------------

        if (original_nal_type == 5)
        {
            bpf_trace_printk(
                "H264 FU-A IDR\n"
            );
        }
        else
        {
            bpf_trace_printk(
                "H264 FU-A NON-IDR\n"
            );
        }
    }


    // =========================================================
    // 12. PASSA O PACOTE
    // =========================================================

    return XDP_PASS;
}