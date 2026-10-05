#!/usr/bin/env python3

from bcc import BPF
import time
import sys
import csv
import os
import socket
import struct
import ctypes


INTERFACE = "eth1"

TIMEOUT_INATIVIDADE = 5.0

ARQUIVO_CSV = "pacotes_I.csv"


# ============================================================
# Estrutura igual à struct packet_info do C
# ============================================================

class PacketInfo(ctypes.Structure):

    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),

        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),

        ("nal_type", ctypes.c_uint8),

        ("fu_start", ctypes.c_uint8),
        ("fu_end", ctypes.c_uint8),
    ]


# ============================================================
# XDP
# ============================================================

def anexar_xdp(bpf, fn, interface):

    try:

        bpf.attach_xdp(
            interface,
            fn,
            0
        )

    except Exception as e:

        print("Erro ao anexar XDP:")
        print(e)

        sys.exit(1)


def remover_xdp(bpf, interface):

    try:

        bpf.remove_xdp(
            interface,
            0
        )

    except:

        pass


# ============================================================
# IP
# ============================================================

def ip_para_string(ip):

    return socket.inet_ntoa(
        struct.pack(
            "I",
            ip
        )
    )


# ============================================================
# CSV
# ============================================================

def preparar_csv():

    # Cria o arquivo e o cabeçalho somente
    # se ele ainda não existir.

    if not os.path.exists(ARQUIVO_CSV):

        with open(
            ARQUIVO_CSV,
            "w",
            newline="",
            encoding="utf-8"
        ) as f:

            escritor = csv.writer(f)

            escritor.writerow([
                "Ordem",
                "Tipo",
                "IP_origem",
                "IP_destino",
                "Porta_origem",
                "Porta_destino",
                "NAL_type",
                "FU_start",
                "FU_end"
            ])


# ============================================================
# SALVAR HASH
# ============================================================

def salvar_hash(pacotes_i):

    quantidade = 0

    # --------------------------------------------------------
    # Copia as entradas do HASH
    # --------------------------------------------------------

    entradas = []

    for chave, valor in pacotes_i.items():

        entradas.append(
            (
                chave.value,
                valor
            )
        )

    # --------------------------------------------------------
    # O BPF_HASH não garante ordem de iteração.
    #
    # Por isso ordenamos pela chave.
    # --------------------------------------------------------

    entradas.sort(
        key=lambda item: item[0]
    )

    # --------------------------------------------------------
    # Grava no CSV
    # --------------------------------------------------------

    with open(
        ARQUIVO_CSV,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        escritor = csv.writer(f)

        for chave, valor in entradas:

            info = valor

            # ------------------------------------------------
            # IPs
            # ------------------------------------------------

            ip_origem = ip_para_string(
                info.src_ip
            )

            ip_destino = ip_para_string(
                info.dst_ip
            )

            # ------------------------------------------------
            # Portas
            # ------------------------------------------------

            porta_origem = socket.ntohs(
                info.src_port
            )

            porta_destino = socket.ntohs(
                info.dst_port
            )

            # ------------------------------------------------
            # Grava somente as informações desejadas
            # ------------------------------------------------

            escritor.writerow([
                chave,
                "I",
                ip_origem,
                ip_destino,
                porta_origem,
                porta_destino,
                info.nal_type,
                info.fu_start,
                info.fu_end
            ])

            quantidade += 1

    return quantidade


# ============================================================
# LIMPAR MAPA
# ============================================================

def limpar_mapas(pacotes_i, contador_i):

    # --------------------------------------------------------
    # Limpa todas as entradas do mapa
    # --------------------------------------------------------

    chaves = list(
        pacotes_i.keys()
    )

    for chave in chaves:

        del pacotes_i[chave]

    # --------------------------------------------------------
    # Reinicia o contador
    # --------------------------------------------------------

    chave_zero = ctypes.c_uint32(0)

    valor_zero = ctypes.c_uint32(0)

    contador_i[chave_zero] = valor_zero


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

if __name__ == "__main__":

    preparar_csv()

    b = None

    try:

        # ====================================================
        # CARREGA eBPF
        # ====================================================

        b = BPF(
            src_file="c.bpf.c"
        )

        fn = b.load_func(
            "ebpf_xdp",
            BPF.XDP
        )

        # ====================================================
        # XDP
        # ====================================================

        anexar_xdp(
            b,
            fn,
            INTERFACE
        )

        print(
            f"XDP carregado em {INTERFACE}"
        )

        print(
            "Mapa: pacotes_i"
        )

        print(
            "Cada pacote I terá uma entrada no mapa."
        )

        print(
            "Aguardando transmissão...\n"
        )

        # ====================================================
        # MAPAS
        # ====================================================

        pacotes_i = b["pacotes_i"]

        contador_i = b["contador_i"]

        # ====================================================
        # CONTROLE DA TRANSMISSÃO
        # ====================================================

        ultima_quantidade = 0

        ultima_atividade = time.time()

        em_transmissao = False

        # ====================================================
        # LOOP
        # ====================================================

        while True:

            time.sleep(1)

            quantidade = len(
                pacotes_i
            )

            # -----------------------------------------------
            # Novo pacote detectado
            # -----------------------------------------------

            if quantidade > ultima_quantidade:

                ultima_quantidade = quantidade

                ultima_atividade = time.time()

                em_transmissao = True

            # -----------------------------------------------
            # Transmissão acontecendo
            # -----------------------------------------------

            if em_transmissao:

                inativo = (
                    time.time()
                    - ultima_atividade
                )

                print(
                    f"\rEntradas no mapa: "
                    f"{quantidade} | "
                    f"Inativo há: "
                    f"{inativo:.1f}s",
                    end="",
                    flush=True
                )

                # -------------------------------------------
                # Fim da transmissão
                # -------------------------------------------

                if inativo >= TIMEOUT_INATIVIDADE:

                    print("\n")

                    print(
                        "================================"
                    )

                    print(
                        "FIM DA TRANSMISSÃO"
                    )

                    print(
                        "================================"
                    )

                    print(
                        f"Pacotes I no mapa: "
                        f"{quantidade}"
                    )

                    # ---------------------------------------
                    # Salva HASH
                    # ---------------------------------------

                    salvos = salvar_hash(
                        pacotes_i
                    )

                    print(
                        f"Pacotes gravados no CSV: "
                        f"{salvos}"
                    )

                    # ---------------------------------------
                    # Limpa mapa e contador
                    # ---------------------------------------

                    limpar_mapas(
                        pacotes_i,
                        contador_i
                    )

                    print(
                        "Mapa e contador eBPF limpos."
                    )

                    print(
                        "Aguardando próxima transmissão...\n"
                    )

                    # ---------------------------------------
                    # Reinicia controle
                    # ---------------------------------------

                    ultima_quantidade = 0

                    ultima_atividade = time.time()

                    em_transmissao = False

            else:

                print(
                    "\rAguardando transmissão...",
                    end="",
                    flush=True
                )

    # ========================================================
    # CTRL+C
    # ========================================================

    except KeyboardInterrupt:

        print(
            "\n\nEncerrando..."
        )

        if b is not None:

            remover_xdp(
                b,
                INTERFACE
            )

        sys.exit(0)

    # ========================================================
    # OUTROS ERROS
    # ========================================================

    except Exception as e:

        print(
            "\n\nErro:"
        )

        print(e)

        if b is not None:

            remover_xdp(
                b,
                INTERFACE
            )

        sys.exit(1)