#!/usr/bin/env python3

from bcc import BPF
import time
import ctypes
import sys

# ============================================================
# Configurações
# ============================================================

INTERFACE = "eth1"       # Interface de rede
ARQUIVO_C = "d.bpf.c"  # Arquivo com o código XDP

# ============================================================
# Carregar programa XDP
# ============================================================

try:
    b = BPF(src_file=ARQUIVO_C)
    function = b.load_func("ebpf_xdp", BPF.XDP)

except Exception as e:
    print(f"Erro ao carregar o programa XDP: {e}")
    sys.exit(1)

# ============================================================
# Anexar XDP à interface
# ============================================================

try:
    b.attach_xdp(INTERFACE, function, 0)
    print(f"XDP anexado à interface {INTERFACE}")
    print("Pressione Ctrl+C para encerrar.\n")

except Exception as e:
    print(f"Erro ao anexar XDP: {e}")
    sys.exit(1)

# ============================================================
# Exibir contadores
# ============================================================

try:
    while True:
        time.sleep(1)

        idr = b["packet_count"].get(ctypes.c_uint(0))
        non_idr = b["packet_count"].get(ctypes.c_uint(1))

        total_idr = idr.value if idr else 0
        total_non_idr = non_idr.value if non_idr else 0

        print(
            f"\rAUs IDR identificadas: {total_idr} | "
            f"Pacotes Non-IDR: {total_non_idr}",
            end="",
            flush=True
        )

except KeyboardInterrupt:
    print("\nEncerrando programa...")

finally:
    b.remove_xdp(INTERFACE, 0)
    print(f"XDP removido da interface {INTERFACE}.")
