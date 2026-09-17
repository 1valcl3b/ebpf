#!/usr/bin/env python3

from bcc import BPF
from pyroute2 import IPRoute

import time
import sys
import csv
import os


INTERFACE = "eth1"

TYPE_IDR = 0
TYPE_NON_IDR = 1




def contadores(bpf):

    tabela = bpf.get_table("packet_count")

    idr = 0
    non_idr = 0 

    for key, value in tabela.items():

        if   key.value == TYPE_IDR:
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

        b = BPF(src_file="classificador-tc.bpf.c")


        fn = b.load_func("ebpf_tc",BPF.SCHED_CLS)

        ip = IPRoute()

        interface_index = ip.link_lookup(ifname=INTERFACE)[0]

        try:

            ip.tc("add","clsact",interface_index)

        except Exception:


            pass



        ip.tc("add-filter","bpf",interface_index,":1",fd=fn.fd,name="ebpf_tc",parent="ffff:fff3",classid=1,direct_action=True)


        print(f"TC eBPF carregado na interface {INTERFACE}")



        while True:

            contadores(b)

            time.sleep(1)


    except KeyboardInterrupt:

        print("\nRemovendo TC eBPF...")


        if 'b' in locals():

            contadores(b)


    except Exception as e:

        print("\nErro:")
        print(e)


    finally:


        if ip:

            try:

                ip.tc("del","clsact",interface_index)

            except Exception:

                pass

            ip.close()


        sys.exit(0)