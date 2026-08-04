#!/usr/bin/env python3


from bcc import BPF
import time

interface = "eth1"

b = BPF(src_file="monitor.bpf.c")

fn = b.load_func("chegou", BPF.XDP)

b.attach_xdp(interface, fn, 0)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(interface, 0)
    print("Programa encerrado e retirado")


