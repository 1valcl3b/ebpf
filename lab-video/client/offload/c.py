#!/usr/bin/env python3
import argparse
import ctypes
import signal
import sys
import time
from bcc import BPF

# Mapeamento dos nomes dos contadores para exibição no terminal
METRIC_NAMES = {
    0: "RTP Total",
    1: "IDR Passou (Pass)",
    2: "IDR Descartado (Drop)",
    3: "Non-IDR Passou (Pass)",
    4: "Non-IDR Descartado (Drop)",
    5: "Gaps de Sequência (Gaps)"
}

def main():
    parser = argparse.ArgumentParser(description="Carregador XDP e Monitor de Métricas H.264")
    parser.add_argument("-i", "--interface", default="eth1", help="Interface de rede (ex: eth1, eth0, vnet1)")
    parser.add_argument("-c", "--code", default="c.bpf.c", help="Caminho para o arquivo C com o código eBPF")
    args = parser.parse_args()

    interface = args.interface

    print(f"[*] Carregando o código eBPF de '{args.code}'...")
    try:
        b = BPF(src_file=args.code)
        fn = b.load_func("ebpf_xdp", BPF.XDP)
    except Exception as e:
        print(f"[!] Erro ao compilar/carregar o código eBPF: {e}")
        sys.exit(1)

    print(f"[*] Anexando o programa XDP à interface '{interface}'...")
    try:
        b.attach_xdp(interface, fn, 0)
    except Exception as e:
        print(f"[!] Erro ao anexar XDP na interface {interface}: {e}")
        sys.exit(1)

    # Tratamento para remover o XDP graciosamente ao pressionar Ctrl+C
    def signal_handler(sig, frame):
        print(f"\n[*] Desanexando XDP da interface '{interface}'...")
        b.remove_xdp(interface, 0)
        print("[*] Finalizado com sucesso.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print(f"[+] Programa eBPF/XDP rodando com sucesso na interface '{interface}'.")
    print("[+] Pressione Ctrl+C para encerrar e desanexar.\n")

    # Loop de monitoramento das métricas
    packet_count_map = b.get_table("packet_count")

    while True:
        try:
            time.sleep(2)
            print("=" * 45)
            print(f"  Métricas do Filtro RTP/XDP - Interface: {interface}")
            print("=" * 45)

            for key_id, name in METRIC_NAMES.items():
                # Converte o ID da chave para uint32 do C usando ctypes
                key = ctypes.c_uint32(key_id)
                val = packet_count_map.get(key)
                count = val.value if val else 0
                print(f"  {name:<28}: {count}")

            print("-" * 45)

        except KeyboardInterrupt:
            signal_handler(None, None)

if __name__ == "__main__":
    main()
