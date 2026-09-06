#!/usr/bin/env python3

from bcc import BPF
from pyroute2 import IPRoute

import time
import sys


INTERFACE = "eth1"

TYPE_IDR = 0
TYPE_NON_IDR = 1


def mostrar_contadores(bpf):

    tabela = bpf.get_table("packet_count")

    idr = 0
    non_idr = 0


    for key, value in tabela.items():

        if key.value == TYPE_IDR:
            idr = value.value

        elif key.value == TYPE_NON_IDR:
            non_idr = value.value


    print("\n==============================")
    print(" PACOTES H.264 ENVIADOS")
    print("==============================")

    print(f"Pacotes IDR enviados     : {idr}")
    print(f"Pacotes Non-IDR enviados : {non_idr}")

    print("==============================")


if __name__ == "__main__":

    ip = None

    try:

        # =====================================================
        # CARREGA O PROGRAMA eBPF
        # =====================================================

        b = BPF(
            src_file="classificador-tc.bpf.c"
        )


        # =====================================================
        # CARREGA A FUNÇÃO COMO TC
        # =====================================================

        fn = b.load_func(
            "ebpf_tc",
            BPF.SCHED_CLS
        )


        # =====================================================
        # ACESSA A INTERFACE
        # =====================================================

        ip = IPRoute()

        interface_index = ip.link_lookup(
            ifname=INTERFACE
        )[0]


        # =====================================================
        # CRIA CLSACT
        # =====================================================

        try:

            ip.tc(
                "add",
                "clsact",
                interface_index
            )

        except Exception:

            # Pode já existir
            pass


        # =====================================================
        # ANEXA eBPF NO EGRESS
        # =====================================================

        ip.tc(
            "add-filter",
            "bpf",
            interface_index,
            ":1",
            fd=fn.fd,
            name="ebpf_tc",
            parent="ffff:fff3",
            classid=1,
            direct_action=True
        )


        print(
            f"TC eBPF carregado na interface {INTERFACE}"
        )

        print("Direção: EGRESS")

        print("Pressione CTRL+C para sair")


        # =====================================================
        # LOOP
        # =====================================================

        while True:

            mostrar_contadores(b)

            time.sleep(1)


    except KeyboardInterrupt:

        print("\nRemovendo TC eBPF...")


        if 'b' in locals():

            mostrar_contadores(b)


    except Exception as e:

        print("\nErro:")
        print(e)


    finally:

        # =====================================================
        # REMOVE CLSACT
        # =====================================================

        if ip:

            try:

                ip.tc(
                    "del",
                    "clsact",
                    interface_index
                )

            except Exception:

                pass

            ip.close()


        sys.exit(0)