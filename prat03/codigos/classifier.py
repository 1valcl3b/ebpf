#!/usr/bin/env python3

from bcc import BPF
import time
import sys


IFACE = "eth1"

def anexar_xdp(bpf, fn, iface):
    try:
        bpf.attach_xdp(iface, fn, 0)
    except Exception as e:
        print("Erro ao anexar XDP:", e)
        sys.exit(1)

def remover_xdp(bpf, iface):
    try:
        bpf.remove_xdp(iface, 0)
    except:
        pass

if __name__ == "__main__":
    try:
        b = BPF(src_file="classificador.bpf.c")
        fn = b.load_func("ebpf_xdp", BPF.XDP)
        anexar_xdp(b, fn, IFACE)

        print(f"XDP carregado na interface {IFACE}")
        print("Pressione CTRL+C para sair")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nRemovendo XDP...")
        remover_xdp(b, IFACE)
        sys.exit(0)