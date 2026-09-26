#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

#define DEST_PORT 5004

#define TYPE_IDR       0
#define TYPE_NON_IDR   1

BPF_HASH(packet_count, __u32, __u64);


// =============================================================
// Incrementa contador
// =============================================================

static __always_inline __u64 incrementar_contador(__u32 key)
{
    __u64 *valor;

    valor = packet_count.lookup(&key);

    if (valor) {

        __sync_fetch_and_add(valor, 1);

        return *valor;
    }

    else {

        __u64 inicial = 1;

        packet_count.update(&key, &inicial);

        return 1;
    }
}


// =============================================================
// XDP
// =============================================================

int ebpf_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;


    // =========================================================
    // Ethernet
    // =========================================================

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;


    // =========================================================
    // IPv4
    // =========================================================

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->daddr != __constant_htonl(0x0A000002))
        return XDP_PASS;


    __u32 ip_hdr_len = ip->ihl * 4;

    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;


    // =========================================================
    // UDP
    // =========================================================

    struct udphdr *udp =
        (struct udphdr *)((void *)ip + ip_hdr_len);

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != __constant_htons(DEST_PORT))
        return XDP_PASS;


    // =========================================================
    // RTP
    // =========================================================

    __u8 *rtp = (__u8 *)(udp + 1);

    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;

    __u8 version = (rtp[0] >> 6) & 0x03;

    if (version != 2)
        return XDP_PASS;


    __u8 *payload = rtp + 12;

    if ((void *)(payload + 2) > data_end)
        return XDP_PASS;


    // =========================================================
    // H.264
    // =========================================================

    __u8 nal_type = payload[0] & 0x1F;


    // =========================================================
    // IDR / NAL unit completo
    // =========================================================

    if (nal_type == 5) {

        __u64 numero = incrementar_contador(TYPE_IDR);

        /*
         * A cada 10 pacotes IDR:
         *
         * 10 -> DROP
         * 20 -> DROP
         * 30 -> DROP
         * ...
         */

        if (numero % 10 == 0)
            return XDP_DROP;

        return XDP_PASS;
    }


    // =========================================================
    // Non-IDR / NAL unit completo
    // =========================================================

    if (nal_type == 1) {

        incrementar_contador(TYPE_NON_IDR);

        return XDP_PASS;
    }


    // =========================================================
    // FU-A
    // =========================================================

    if (nal_type == 28) {

        __u8 fu_header = payload[1];

        __u8 original_nal_type = fu_header & 0x1F;


        // -----------------------------------------------------
        // FU-A IDR
        // -----------------------------------------------------

        if (original_nal_type == 5) {

            __u64 numero = incrementar_contador(TYPE_IDR);

            /*
             * Descarta 1 a cada 10 IDR.
             */
            if (numero % 10 == 0)
                return XDP_DROP;

            return XDP_PASS;
        }


        // -----------------------------------------------------
        // FU-A Non-IDR
        // -----------------------------------------------------

        if (original_nal_type == 1) {

            incrementar_contador(TYPE_NON_IDR);

            return XDP_PASS;
        }
    }


    // =========================================================
    // Outros pacotes
    // =========================================================

    return XDP_PASS;
}
