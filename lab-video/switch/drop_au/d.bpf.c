#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

#define DEST_PORT 5004

#define TYPE_IDR       0
#define TYPE_NON_IDR   1

#define intervalo_au 5

// =============================================================
// Contadores
// =============================================================

BPF_HASH(packet_count, __u32, __u64);


// =============================================================
// Estado da AU atual
// =============================================================

struct au_state {
    __u32 timestamp;
    __u8 initialized;
    __u8 idr_counted;
    __u8 drop_current_au;
};

BPF_HASH(au_state_map, __u32, struct au_state);


// =============================================================
// Incrementa contador
// =============================================================

static __always_inline __u64 incrementar_contador(__u32 key)
{
    __u64 *valor = packet_count.lookup(&key);

    if (valor) {
        __sync_fetch_and_add(valor, 1);
        return *valor;
    }

    __u64 inicial = 1;
    packet_count.update(&key, &inicial);

    return inicial;
}


// =============================================================
// XDP
// =============================================================

int ebpf_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

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

    // Destino: 10.0.0.2
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
    // RTP - cabeçalho fixo de 12 bytes
    // =========================================================

    __u8 *rtp = (__u8 *)(udp + 1);

    if ((void *)(rtp + 12) > data_end)
        return XDP_PASS;

    __u8 version = (rtp[0] >> 6) & 0x03;

    if (version != 2)
        return XDP_PASS;

    // Timestamp RTP
    __u32 timestamp =
          ((__u32)rtp[4] << 24)
        | ((__u32)rtp[5] << 16)
        | ((__u32)rtp[6] << 8)
        |  (__u32)rtp[7];

    // Marker RTP
    __u8 marker = (rtp[1] & 0x80) != 0;

    __u8 *payload = rtp + 12;

    if ((void *)(payload + 1) > data_end)
        return XDP_PASS;


    // =========================================================
    // Estado da AU
    // =========================================================

    __u32 state_key = 0;

    struct au_state initial_state = {};

    struct au_state *state =
        au_state_map.lookup(&state_key);

    if (!state) {
        au_state_map.update(&state_key, &initial_state);

        state = au_state_map.lookup(&state_key);

        if (!state)
            return XDP_PASS;
    }

    // Novo timestamp: inicia o estado de outra AU.
    if (!state->initialized ||
        state->timestamp != timestamp) {

        state->timestamp = timestamp;
        state->initialized = 1;
        state->idr_counted = 0;
        state->drop_current_au = 0;
    }


    // =========================================================
    // Descartar pacotes da AU selecionada
    // =========================================================

    if (state->drop_current_au) {

        // Marker indica o último pacote da AU.
        if (marker)
            state->drop_current_au = 0;

        return XDP_DROP;
    }


    // =========================================================
    // Identificar NAL H.264
    // =========================================================

    __u8 nal_type = payload[0] & 0x1F;

    __u8 is_idr_start = 0;


    // ---------------------------------------------------------
    // NAL IDR não fragmentada
    // ---------------------------------------------------------

    if (nal_type == 5) {
        is_idr_start = 1;
    }


    // ---------------------------------------------------------
    // FU-A
    // ---------------------------------------------------------

    else if (nal_type == 28) {

        if ((void *)(payload + 2) > data_end)
            return XDP_PASS;

        __u8 fu_header = payload[1];

        __u8 original_nal_type = fu_header & 0x1F;
        __u8 fu_start = (fu_header & 0x80) != 0;

        // FU-A IDR: reconhecer somente no primeiro fragmento.
        if (original_nal_type == 5 && fu_start) {
            is_idr_start = 1;
        }

        // Contagem de pacotes Non-IDR fragmentados.
        else if (original_nal_type == 1) {
            incrementar_contador(TYPE_NON_IDR);
        }
    }


    // ---------------------------------------------------------
    // NAL Non-IDR não fragmentada
    // ---------------------------------------------------------

    else if (nal_type == 1) {
        incrementar_contador(TYPE_NON_IDR);
    }


    // =========================================================
    // Contar AU IDR e decidir descarte
    // =========================================================

    if (is_idr_start && !state->idr_counted) {

        state->idr_counted = 1;

        __u64 numero = incrementar_contador(TYPE_IDR);

        // Descarta a 10ª, 20ª, 30ª... AU IDR.
        if (numero % intervalo_au == 0) {

            state->drop_current_au = 1;

            // Se este já for o último pacote da AU,
            // não é necessário manter o estado de descarte.
            if (marker)
                state->drop_current_au = 0;

            return XDP_DROP;
        }
    }


    // =========================================================
    // Demais pacotes
    // =========================================================

    return XDP_PASS;
}