#include <uapi/linux/if_ether.h>

#include <uapi/linux/ip.h>

#include <uapi/linux/udp.h>

#include <linux/in.h>

#include <uapi/linux/bpf.h>

#include <linux/types.h>

#define DEST_PORT 5004

// Contadores

#define COUNT_RTP_TOTAL          0

#define COUNT_IDR_SEEN           1

#define COUNT_NON_IDR_SEEN       2

#define COUNT_SEQUENCE_GAPS      3

#define COUNT_LOST_ESTIMATED     4

#define COUNT_IDR_AU_VALID       5

#define COUNT_IDR_AU_INCOMPLETE  6

#define COUNT_IDR_PASS           7

#define COUNT_IDR_DROP           8

#define COUNT_NON_IDR_PASS       9

#define COUNT_NON_IDR_DROP       10

// Contadores compartilhados com o Python.
BPF_HASH(packet_count, __u32, __u64);

// Eventos detalhados enviados do kernel ao Python para CSV.
// event_type: 1 = pacote; 2 = AU IDR fechada.
// action: 0 = DROP; 1 = PASS; 2 = nao aplicavel (evento de AU).
// au_status: 0 = nao aplicavel; 1 = valida; 2 = incompleta.
struct debug_event {
    __u64 tempo_ns;
    __u32 rtp_timestamp;
    __u32 au_timestamp;
    __u32 lost_estimated;
    __u16 seq;
    __u8 event_type;
    __u8 nal_type;       // Tipo NAL RTP externo; 28 significa FU-A.
    __u8 h264_type;      // Tipo NAL original; 1 = Non-IDR, 5 = IDR.
    __u8 marker;
    __u8 fu_start;
    __u8 fu_end;
    __u8 gap_detected;
    __u8 au_broken;
    __u8 waiting_for_idr;
    __u8 action;
    __u8 au_status;
    __u8 au_close_reason; // 0 = N/A; 1 = Marker; 2 = timestamp mudou sem Marker.
};

BPF_PERF_OUTPUT(debug_events);

// ============================================================

// ESTADO DO FLUXO RTP

// ============================================================

struct stream_state {

    __u16 last_seq;

    __u8 has_last_seq;

    // 1 = aguardando uma nova IDR válida

    __u8 waiting_for_idr;

    // Estado da Access Unit atual

    __u8 au_active;

    __u8 au_has_idr;

    __u8 au_broken;

    __u32 au_timestamp;

};

// Estamos considerando um único fluxo RTP.

BPF_HASH(stream_state_map, __u32, struct stream_state, 1);

// ============================================================

// CONTADORES

// ============================================================

static __always_inline void adicionar_contador(

    __u32 key,

    __u64 quantidade

)

{

    __u64 *valor = packet_count.lookup(&key);

    if (valor) {

        __sync_fetch_and_add(valor, quantidade);

    } else {

        __u64 inicial = quantidade;

        packet_count.update(&key, &inicial);

    }

}

// ============================================================

// CONTROLE DA ACCESS UNIT

// ============================================================

// Envia um registro de pacote com o estado no momento da decisao.
static __always_inline void emitir_evento_pacote(
    struct xdp_md *ctx,
    struct debug_event *evento,
    struct stream_state *estado,
    __u8 action
)
{
    evento->tempo_ns = bpf_ktime_get_ns();
    evento->event_type = 1;
    evento->action = action;
    evento->au_broken = estado ? estado->au_broken : 0;
    evento->waiting_for_idr = estado ? estado->waiting_for_idr : 1;
    evento->au_status = 0;
    debug_events.perf_submit(ctx, evento, sizeof(*evento));
}

// Registra o fechamento de uma AU que continha IDR.
static __always_inline void emitir_evento_au(
    struct xdp_md *ctx,
    struct debug_event *pacote_atual,
    struct stream_state *estado,
    __u8 status,
    __u8 close_reason
)
{
    struct debug_event evento = *pacote_atual;
    evento.tempo_ns = bpf_ktime_get_ns();
    evento.event_type = 2;
    evento.au_timestamp = estado->au_timestamp;
    evento.au_broken = estado->au_broken;
    evento.waiting_for_idr = estado->waiting_for_idr;
    evento.action = 2;
    evento.au_status = status;
    evento.au_close_reason = close_reason;
    debug_events.perf_submit(ctx, &evento, sizeof(evento));
}

static __always_inline void limpar_au(

    struct stream_state *estado

)

{

    estado->au_active = 0;

    estado->au_has_idr = 0;

    estado->au_broken = 0;

    estado->au_timestamp = 0;

}

// Uma nova timestamp comecou sem que a AU anterior apresentasse Marker.
static __always_inline void fechar_au_sem_marker(
    struct xdp_md *ctx,
    struct stream_state *estado,
    struct debug_event *pacote_atual
)
{
    if (estado->au_active) {
        if (estado->au_has_idr) {
            adicionar_contador(COUNT_IDR_AU_INCOMPLETE, 1);
            estado->waiting_for_idr = 1;
            emitir_evento_au(ctx, pacote_atual, estado, 2, 2);
        }
        limpar_au(estado);
    }
}

// O pacote Marker encerrou a Access Unit atual.
static __always_inline void fechar_au_com_marker(
    struct xdp_md *ctx,
    struct stream_state *estado,
    struct debug_event *pacote_atual
)
{
    if (estado->au_active) {
        if (estado->au_has_idr) {
            if (estado->au_broken) {
                adicionar_contador(COUNT_IDR_AU_INCOMPLETE, 1);
                estado->waiting_for_idr = 1;
                emitir_evento_au(ctx, pacote_atual, estado, 2, 1);
            } else {
                adicionar_contador(COUNT_IDR_AU_VALID, 1);
                estado->waiting_for_idr = 0;
                emitir_evento_au(ctx, pacote_atual, estado, 1, 1);
            }
        }
        limpar_au(estado);
    }
}

// ============================================================

// XDP

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

    // ========================================================

    // UDP

    // ========================================================

    struct udphdr *udp =

        (struct udphdr *)((void *)ip + ip_hdr_len);

    if ((void *)(udp + 1) > data_end)

        return XDP_PASS;

    if (udp->dest != __constant_htons(DEST_PORT))

        return XDP_PASS;

    // ========================================================

    // RTP: CABEÇALHO FIXO

    // ========================================================

    __u8 *rtp = (__u8 *)(udp + 1);

    if ((void *)(rtp + 12) > data_end)

        return XDP_PASS;

    __u8 version = (rtp[0] >> 6) & 0x03;

    if (version != 2)

        return XDP_PASS;

    // Sequence Number: 16 bits

    __u16 sequence =

        ((__u16)rtp[2] << 8) |

        (__u16)rtp[3];

    // Timestamp: 32 bits

    __u32 timestamp =

        ((__u32)rtp[4] << 24) |

        ((__u32)rtp[5] << 16) |

        ((__u32)rtp[6] << 8)  |

        (__u32)rtp[7];

    // Marker: bit mais significativo do segundo byte

    __u8 marker = (rtp[1] >> 7) & 0x01;

    // ========================================================

    // RTP: CABEÇALHO FIXO DE 12 BYTES

    // ========================================================

    // Esta implementação assume RTP sem CSRCs nem extensões.

    // O fluxo FFmpeg usado no experimento deve atender a essa condição.

    __u32 rtp_header_len = 12;

    if ((void *)(rtp + rtp_header_len) > data_end)

        return XDP_PASS;

    // ========================================================

    // PAYLOAD RTP

    // ========================================================

    __u8 *payload = rtp + rtp_header_len;

    if ((void *)(payload + 1) > data_end)

        return XDP_PASS;

    adicionar_contador(COUNT_RTP_TOTAL, 1);

    // ========================================================

    // CLASSIFICAÇÃO H.264

    // ========================================================

    __u8 nal_type = payload[0] & 0x1F;

    __u8 is_idr = 0;

    __u8 is_non_idr = 0;

    __u8 is_fu_a = 0;

    __u8 fu_start = 0;
    __u8 fu_end = 0;
    __u8 h264_type = nal_type;

    if (nal_type == 5) {

        // NAL IDR completa.

        is_idr = 1;

    } else if (nal_type == 1) {

        // NAL Non-IDR completa.

        is_non_idr = 1;

    } else if (

        nal_type == 28 &&

        (void *)(payload + 2) <= data_end

    ) {

        // Fragmentation Unit A.

        is_fu_a = 1;

        __u8 fu_header = payload[1];

        __u8 original_nal_type = fu_header & 0x1F;

        h264_type = original_nal_type;
        fu_start = (fu_header >> 7) & 0x01;
        fu_end = (fu_header >> 6) & 0x01;

        if (original_nal_type == 5) {

            is_idr = 1;

        } else if (original_nal_type == 1) {

            is_non_idr = 1;

        }

    }

    if (is_idr) {

        adicionar_contador(COUNT_IDR_SEEN, 1);

    } else if (is_non_idr) {

        adicionar_contador(COUNT_NON_IDR_SEEN, 1);

    }

    // ========================================================

    // OBTÉM O ESTADO DO FLUXO

    // ========================================================

    __u32 state_key = 0;

    struct stream_state *estado =

        stream_state_map.lookup(&state_key);

    if (!estado) {

        struct stream_state inicial = {};

        // Até reconhecer uma IDR completa, não liberamos Non-IDR.

        inicial.waiting_for_idr = 1;

        stream_state_map.update(&state_key, &inicial);

        estado = stream_state_map.lookup(&state_key);

        if (!estado)

            return XDP_PASS;

    }

    // Metadados compartilhados por todos os registros deste pacote.
    struct debug_event evento = {};
    evento.seq = sequence;
    evento.rtp_timestamp = timestamp;
    evento.au_timestamp = timestamp;
    evento.nal_type = nal_type;
    evento.h264_type = h264_type;
    evento.marker = marker;
    evento.fu_start = fu_start;
    evento.fu_end = fu_end;

    // ========================================================

    // DETECÇÃO DE PERDA PELO SEQUENCE NUMBER

    // ========================================================

    __u8 gap_detected = 0;
    __u32 lost_estimated = 0;

    if (!estado->has_last_seq) {

        estado->last_seq = sequence;

        estado->has_last_seq = 1;

    } else {

        __u16 delta =

            (__u16)(sequence - estado->last_seq);

        /*

         * Delta igual a zero:

         *   possível duplicata.

         *

         * Delta >= 32768:

         *   provável pacote antigo ou fora de ordem.

         *

         * Não tratamos esses casos como perda nova.

         */

        if (delta == 0 || delta >= 0x8000) {

            if (is_idr) {

                if (estado->au_active && estado->au_broken) {

                    adicionar_contador(COUNT_IDR_DROP, 1);
                    emitir_evento_pacote(ctx, &evento, estado, 0);
                    return XDP_DROP;

                }

                adicionar_contador(COUNT_IDR_PASS, 1);
                emitir_evento_pacote(ctx, &evento, estado, 1);
                return XDP_PASS;

            }

            if (is_non_idr) {

                if (estado->waiting_for_idr) {

                    adicionar_contador(COUNT_NON_IDR_DROP, 1);
                    emitir_evento_pacote(ctx, &evento, estado, 0);
                    return XDP_DROP;

                }

                adicionar_contador(COUNT_NON_IDR_PASS, 1);
                emitir_evento_pacote(ctx, &evento, estado, 1);
            } else {
                emitir_evento_pacote(ctx, &evento, estado, 1);
            }

            return XDP_PASS;

        }

        if (delta > 1) {

            gap_detected = 1;
            evento.gap_detected = 1;
            lost_estimated = (__u32)(delta - 1);
            evento.lost_estimated = lost_estimated;

            adicionar_contador(COUNT_SEQUENCE_GAPS, 1);

            // Número estimado de pacotes ausentes.

            adicionar_contador(

                COUNT_LOST_ESTIMATED,

                (__u64)(delta - 1)

            );

            // Entramos em modo de recuperação.

            estado->waiting_for_idr = 1;

        }

        estado->last_seq = sequence;

    }

    // ========================================================

    // VERIFICA A ACCESS UNIT PELO TIMESTAMP

    // ========================================================

    __u8 mesma_au =

        estado->au_active &&

        (timestamp == estado->au_timestamp);

    /*

     * Se houve perda dentro da mesma AU, marcamos a AU

     * como comprometida.

     */

    if (gap_detected && mesma_au) {

        estado->au_broken = 1;

    }

    /*

     * Se o timestamp mudou antes do Marker da AU anterior,

     * encerramos a AU anterior como incompleta quando ela

     * continha IDR.

     */

    if (

        estado->au_active &&

        timestamp != estado->au_timestamp

    ) {

        fechar_au_sem_marker(ctx, estado, &evento);

    }

    // ========================================================

    // INICIA OU CONTINUA A ACCESS UNIT ATUAL

    // ========================================================

    if (!estado->au_active) {

        estado->au_active = 1;

        estado->au_timestamp = timestamp;

        estado->au_has_idr = 0;

        estado->au_broken = 0;

        /*

         * Se perdemos um pacote antes de um fragmento FU-A

         * de continuação IDR, a AU atual não pode ser aceita

         * como completa.

         */

        if (

            gap_detected &&

            is_idr &&

            is_fu_a &&

            !fu_start

        ) {

            estado->au_broken = 1;

        }

    } else if (gap_detected) {

        estado->au_broken = 1;

    }

    // Registra se esta AU contém um pacote IDR.

    if (is_idr) {

        estado->au_has_idr = 1;

    }

    // ========================================================

    // DECISÃO: IDR

    // ========================================================

    if (is_idr) {

        if (estado->au_broken) {

            // A AU IDR atual já foi considerada incompleta.

            adicionar_contador(COUNT_IDR_DROP, 1);
            emitir_evento_pacote(ctx, &evento, estado, 0);

            // O pacote não sobe pela pilha de rede.

            if (marker) {

                fechar_au_com_marker(ctx, estado, &evento);

            }

            return XDP_DROP;

        }

        /*

         * Passamos os pacotes IDR que podem formar uma nova

         * AU de referência. Ela só será considerada válida

         * quando a AU for encerrada sem perda identificada.

         */

        adicionar_contador(COUNT_IDR_PASS, 1);
        emitir_evento_pacote(ctx, &evento, estado, 1);

        if (marker) {

            fechar_au_com_marker(ctx, estado, &evento);

        }

        return XDP_PASS;

    }

    // ========================================================

    // DECISÃO: NON-IDR

    // ========================================================

    if (is_non_idr) {

        if (estado->waiting_for_idr) {

            // Ainda não reconhecemos uma nova IDR válida.

            adicionar_contador(COUNT_NON_IDR_DROP, 1);
            emitir_evento_pacote(ctx, &evento, estado, 0);

            if (marker) {

                fechar_au_com_marker(ctx, estado, &evento);

            }

            return XDP_DROP;

        }

        adicionar_contador(COUNT_NON_IDR_PASS, 1);
        emitir_evento_pacote(ctx, &evento, estado, 1);

        if (marker) {

            fechar_au_com_marker(ctx, estado, &evento);

        }

        return XDP_PASS;

    }

    // ========================================================

    // OUTROS NAL TYPES

    // ========================================================

    //

    // SPS, PPS, SEI e outros tipos não classificados acima

    // passam normalmente. O Marker ainda pode fechar a AU.

    // ========================================================

    emitir_evento_pacote(ctx, &evento, estado, 1);

    if (marker) {

        fechar_au_com_marker(ctx, estado, &evento);

    }

    return XDP_PASS;

}
