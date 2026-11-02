// Bloco 1: Inclusão de Cabeçalhos e Definições de Constantes


#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

#define DEST_PORT 5004

#define COUNT_RTP_TOTAL       0
#define COUNT_IDR_PASS        1
#define COUNT_IDR_DROP        2
#define COUNT_NON_IDR_PASS    3
#define COUNT_NON_IDR_DROP    4
#define COUNT_SEQUENCE_GAPS   5

// FIM BLOCO 1


// Bloco 2: Estruturas de Estado, Mapas e Função Auxiliar

BPF_HASH(packet_count, __u32, __u64); // cria um mapa ebpf, do tipo hash table


struct stream_state { // cria uma estrutura de dados para armazenar o estado do fluxo de vídeo.
    __u16 last_seq;
    __u8  has_last_seq;
    
    
    __u8  has_valid_idr;
    __u32 valid_idr_timestamp; 
    
    
    __u8  au_active;
    __u8  au_broken;
    __u32 au_timestamp;
};

BPF_HASH(stream_state_map, __u32, struct stream_state, 1);

static __always_inline void adicionar_contador(__u32 key, __u64 quantidade) // Uma função auxiliar para atualizar as estatísticas de pacotes
{
    __u64 *valor = packet_count.lookup(&key);
    if (valor) {
        __sync_fetch_and_add(valor, quantidade);
    } else {
        __u64 inicial = quantidade;
        packet_count.update(&key, &inicial);
    }
}



// FIM BLOCO 2



// Blocko 3: Início do Programa XDP e Parsing dos Cabeçalhos de Rede

int ebpf_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Parsing Ethernet / IP / UDP ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->daddr != __constant_htonl(0x0A000002)) return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != __constant_htons(DEST_PORT)) return XDP_PASS;

// FIM BLOCO 4



// Bloco 4: Parsing do Cabeçalho RTP e Classificação H.264

    __u8 *rtp = (__u8 *)(udp + 1); // Aponta para o início dos dados do protocolo RTP
    if ((void *)(rtp + 12) > data_end) return XDP_PASS; //verifica se o pacotge tem pelo menos 12 bytes

    if (((rtp[0] >> 6) & 0x03) != 2) return XDP_PASS; // RTP v2

    __u16 sequence = ((__u16)rtp[2] << 8) | (__u16)rtp[3];
    __u32 timestamp = ((__u32)rtp[4] << 24) | ((__u32)rtp[5] << 16) |
                      ((__u32)rtp[6] << 8)  | (__u32)rtp[7];
    __u8 marker = (rtp[1] >> 7) & 0x01;

    __u8 *payload = rtp + 12;
    if ((void *)(payload + 1) > data_end) return XDP_PASS;

    adicionar_contador(COUNT_RTP_TOTAL, 1);

    // --- Classificação H.264 ---
    __u8 nal_type = payload[0] & 0x1F;
    __u8 is_idr = 0;
    __u8 is_non_idr = 0;

    if (nal_type == 5) {
        is_idr = 1;
    } else if (nal_type == 1) {
        is_non_idr = 1;
    } else if (nal_type == 28 && (void *)(payload + 2) <= data_end) { // FU-A
        __u8 original_nal_type = payload[1] & 0x1F;
        if (original_nal_type == 5) is_idr = 1;
        else if (original_nal_type == 1) is_non_idr = 1;
    }

// FIM BLOCO 4



// Bloco 5: Consulta de Estado, Detecção de Perda de Pacotes e Controle da Access Unit (AU)
    __u32 state_key = 0;
    struct stream_state *estado = stream_state_map.lookup(&state_key);
    if (!estado) {
        struct stream_state inicial = {};
        inicial.has_valid_idr = 0; // Inicialmente sem IDR registrada
        stream_state_map.update(&state_key, &inicial);
        estado = stream_state_map.lookup(&state_key);
        if (!estado) return XDP_PASS;
    }

    // --- Detecção de Perda de Pacotes (Sequence Gap) ---
    __u8 gap_detected = 0;
    if (!estado->has_last_seq) {
        estado->last_seq = sequence;
        estado->has_last_seq = 1;
    } else {
        __u16 delta = (__u16)(sequence - estado->last_seq);
        if (delta > 1 && delta < 0x8000) {
            gap_detected = 1;
            adicionar_contador(COUNT_SEQUENCE_GAPS, 1);
            
            // Se perdemos pacotes, a IDR atual torna-se inválida até surgir uma nova completa
            estado->has_valid_idr = 0;
        }
        estado->last_seq = sequence;
    }

    // --- Processamento da Access Unit (AU) ---
    if (!estado->au_active || timestamp != estado->au_timestamp) {
        // Nova AU iniciou
        estado->au_active = 1;
        estado->au_timestamp = timestamp;
        estado->au_broken = gap_detected;
    } else if (gap_detected) {
        estado->au_broken = 1;
    }

    // --- DECISÃO DE DESCARTE (Regras da Tabela) ---

    // 1. Pacote pertencente a um Quadro IDR (AU Keyframe)
    if (is_idr) {
        if (estado->au_broken) {
            estado->has_valid_idr = 0; // IDR incompleta não entra na tabela
            adicionar_contador(COUNT_IDR_DROP, 1);
            return XDP_DROP;
        }

        // Registrar IDR válida na tabela ao finalizar a AU (ou durante a recepção íntegra)
        estado->has_valid_idr = 1;
        estado->valid_idr_timestamp = timestamp;
        adicionar_contador(COUNT_IDR_PASS, 1);
        return XDP_PASS;
    }

    // 2. Pacote pertencente a Quadros Non-IDR (P ou B)
    if (is_non_idr) {
        // Verifica se a IDR de referência deste GOP existe na tabela (has_valid_idr == 1)
        if (!estado->has_valid_idr) {
            // Caso da AU 2 no diagrama: IDR não chegou/foi dropada -> DROPA P e B
            adicionar_contador(COUNT_NON_IDR_DROP, 1);
            return XDP_DROP;
        }

        // Caso da AU 1 e AU 3 no diagrama: IDR válida existe -> PASSA P e B
        adicionar_contador(COUNT_NON_IDR_PASS, 1);
        return XDP_PASS;
    }

    return XDP_PASS;
}
