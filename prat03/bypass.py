#!/usr/bin/env python3

from bcc import BPF
import time
import argparse
import sys

program = BPF(src_file="bypass.bpf.c")

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
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="Interface de entrada (ex: enp1s0)")
    args = parser.parse_args()
    iface = args.iface

    try:
        b = BPF(text=program)
        fn = b.load_func("ebpf_xdp", BPF.XDP)
        anexar_xdp(b, fn, iface)

        print(f"XDP carregado na interface {iface}")
        print("Pressione CTRL+C para sair")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nRemovendo XDP...")
        remover_xdp(b, iface)
        sys.exit(0)



