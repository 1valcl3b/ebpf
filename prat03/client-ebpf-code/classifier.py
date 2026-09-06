#!/usr/bin/env python3

from bcc import BPF
import time
import sys


INTERFACE = "eth1"


def anexar_xdp(bpf, fn, interface):
    try:
        bpf.attach_xdp(interface, fn, 0)
    except Exception as e:
        print("Erro ao anexar XDP:", e)
        sys.exit(1)


def remover_xdp(bpf, interface):
    try:
        bpf.remove_xdp(interface, 0)
    except:
        pass


def mostrar_contadores(bpf):

    tabela = bpf.get_table("packet_count")

    idr = 0
    non_idr = 0

    for key, value in tabela.items():

        if key.value == 0:
            idr = value.value

        elif key.value == 1:
            non_idr = value.value

    print("\n==============================")
    print("      CONTADORES H.264")
    print("==============================")

    print(f"Pacotes IDR     : {idr}")
    print(f"Pacotes Non-IDR : {non_idr}")

    print("==============================\n")


if __name__ == "__main__":

    try:

        
        b = BPF(src_file="classificador.bpf.c")


        fn = b.load_func("ebpf_xdp",BPF.XDP)


        # Anexa XDP
        anexar_xdp(b,fn,INTERFACE)


        print(f"XDP carregado na interface {INTERFACE}")

        print("Pressione CTRL+C para sair")


        while True:

            mostrar_contadores(b)

            time.sleep(1)


    except KeyboardInterrupt:

        print("\nRemovendo XDP...")

        mostrar_contadores(b)

        remover_xdp(b,INTERFACE)

        sys.exit(0)