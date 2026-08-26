#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>

// Função auxiliar para dobrar o checksum (já existente)
static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

// Calcula checksum do cabeçalho IP
static __always_inline __u16 iph_csum(struct iphdr *iph)
{
    iph->check = 0;

    __u64 csum = 0;
    __u16 *next = (__u16 *)iph;

#pragma unroll
    for (int i = 0; i < (sizeof(*iph) >> 1); i++)
        csum += *next++;

    return csum_fold_helper(csum);
}

// Função principal XDP
int ebpf_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Cabeçalho Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // bpf_trace_printk("ETH\n");

    // Apenas IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Cabeçalho IP
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // bpf_trace_printk("IP\n");

    // Apenas UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Filtra pacotes com IP destino 192.168.57.13
    if (ip->daddr != __constant_htonl(0xC0A8390D))
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;

    // Cabeçalho UDP
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // bpf_trace_printk("UDP\n");
    
    // __u16 dport = ntohs(udp->dest);
    
    // bpf_trace_printk("dport=%d\n", dport);
   
   // Filtra porta 2152 (GTP)
    if (udp->dest != __constant_htons(2152))
        return XDP_PASS;
	

    // ----- MODIFICAÇÕES -----

    // 1. Altera MAC destino para o MAC do container upf (7a:51:73:1b:7f:32)
    unsigned char new_dst_mac[6] = {0xd6, 0x2b, 0x29, 0x2d, 0xb0, 0xa4};
    __builtin_memcpy(eth->h_dest, new_dst_mac, 6);

    // 2. Altera MAC origem para o MAC da interface enp1s0 (52:54:00:1b:63:7f)
    unsigned char new_src_mac[6] = {0x52, 0x54, 0x00, 0xad, 0x48, 0xf6};
    __builtin_memcpy(eth->h_source, new_src_mac, 6);

    // Poderia tentar usar o mac da interface br como o de origem:
    // unsigned char new_src_mac[6] = {0x0a, 0xd2, 0x8c, 0x6d, 0x7f, 0xe9};
    // __builtin_memcpy(eth->h_source, new_src_mac, 6);

    // 3. Altera IP destino para 172.22.0.8 - upf (0xAC160008 em hex)
    ip->daddr = __constant_htonl(0xAC160008);

    // 4. Recalcula checksum do IP
    ip->check = iph_csum(ip);

    // 5. Zera o checksum UDP (simplificação: assim o receptor não valida)
    udp->check = 0;

    // ----- REDIRECIONAMENTO -----
    // Redireciona para a interface com ifindex 7 (upf)
    return bpf_redirect(7, 0);
    
}