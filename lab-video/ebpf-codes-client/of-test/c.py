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

ARQUIVO_CSV = "trafego_h264.csv"


# ============================================================
# Estrutura igual à struct packet_info do C
# ============================================================

class PacketInfo(ctypes.Structure):

    _fields_ = [

        ("tipo", ctypes.c_uint8),

        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),

        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),

        ("rtp_seq", ctypes.c_uint16),

        ("rtp_timestamp", ctypes.c_uint32),

        ("rtp_marker", ctypes.c_uint8),

        ("nal_type", ctypes.c_uint8),

        ("fu_start", ctypes.c_uint8),
        ("fu_end", ctypes.c_uint8),

        ("timestamp_ns", ctypes.c_uint64),
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
        struct.pack("I", ip)
    )


# ============================================================
# TIPO
# ============================================================

def tipo_para_string(tipo):

    if tipo == 0:
        return "I"

    return "Non-I"


# ============================================================
# SALVAR MAPA NO CSV
# ============================================================

def salvar_csv(pacotes):

    print("\nSalvando mapa eBPF no CSV...")


    entradas = []


    # --------------------------------------------------------
    # Copia as entradas do mapa
    # --------------------------------------------------------

    for chave, valor in pacotes.items():

        numero = chave.value

        info = PacketInfo.from_buffer_copy(
            bytes(valor)
        )

        entradas.append(
            (numero, info)
        )


    # --------------------------------------------------------
    # Ordena pela ordem global do pacote
    # --------------------------------------------------------

    entradas.sort(
        key=lambda item: item[0]
    )


    # --------------------------------------------------------
    # Cria CSV
    # --------------------------------------------------------

    with open(
        ARQUIVO_CSV,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        escritor = csv.writer(f)


        # Cabeçalho

        escritor.writerow([

            "Ordem",

            "Tipo",

            "Timestamp_kernel_ns",

            "IP_origem",

            "IP_destino",

            "Porta_origem",

            "Porta_destino",

            "RTP_sequence",

            "RTP_timestamp",

            "RTP_marker",

            "NAL_type",

            "FU_start",

            "FU_end"
        ])


        # ----------------------------------------------------
        # Dados
        # ----------------------------------------------------

        for numero, info in entradas:

            ip_origem = ip_para_string(
                info.src_ip
            )

            ip_destino = ip_para_string(
                info.dst_ip
            )


            porta_origem = socket.ntohs(
                info.src_port
            )

            porta_destino = socket.ntohs(
                info.dst_port
            )


            escritor.writerow([

                numero,

                tipo_para_string(
                    info.tipo
                ),

                info.timestamp_ns,

                ip_origem,

                ip_destino,

                porta_origem,

                porta_destino,

                info.rtp_seq,

                info.rtp_timestamp,

                info.rtp_marker,

                info.nal_type,

                info.fu_start,

                info.fu_end
            ])


    # --------------------------------------------------------
    # Estatísticas
    # --------------------------------------------------------

    quantidade_i = 0

    quantidade_non_i = 0


    for numero, info in entradas:

        if info.tipo == 0:

            quantidade_i += 1

        else:

            quantidade_non_i += 1


    print()
    print("========================================")
    print("RESULTADO")
    print("========================================")

    print(
        f"Pacotes I:     {quantidade_i}"
    )

    print(
        f"Pacotes Non-I: {quantidade_non_i}"
    )

    print(
        f"Total:         {len(entradas)}"
    )

    print(
        f"Arquivo:       {ARQUIVO_CSV}"
    )

    print("========================================")


# ============================================================
# LIMPAR MAPA
# ============================================================

def limpar_mapa(pacotes):

    for chave in list(pacotes.keys()):

        del pacotes[chave]


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

if __name__ == "__main__":

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
        # ANEXA XDP
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
            "Mapa: pacotes"
        )

        print(
            "I e Non-I serão armazenados na mesma tabela."
        )

        print(
            "Aguardando transmissão H.264...\n"
        )


        # ====================================================
        # MAPA
        # ====================================================

        pacotes = b["pacotes"]

        contador = b["contador"]


        # ====================================================
        # CONTROLE
        # ====================================================

        ultima_quantidade = 0

        ultima_atividade = time.time()

        em_transmissao = False


        # ====================================================
        # LOOP
        # ====================================================

        while True:

            time.sleep(1)


            quantidade = len(pacotes)


            # ------------------------------------------------
            # Detectou pacote novo
            # ------------------------------------------------

            if quantidade > ultima_quantidade:

                ultima_quantidade = quantidade

                ultima_atividade = time.time()

                em_transmissao = True


            # ------------------------------------------------
            # Transmissão
            # ------------------------------------------------

            if em_transmissao:

                inativo = (
                    time.time()
                    -
                    ultima_atividade
                )


                print(
                    f"\rPacotes no mapa: "
                    f"{quantidade} | "
                    f"Inativo há: "
                    f"{inativo:.1f}s",
                    end="",
                    flush=True
                )


                # --------------------------------------------
                # Fim da transmissão
                # --------------------------------------------

                if inativo >= TIMEOUT_INATIVIDADE:

                    print("\n")


                    print(
                        "========================================"
                    )

                    print(
                        "FIM DA TRANSMISSÃO"
                    )

                    print(
                        "========================================"
                    )


                    # ----------------------------------------
                    # Salva mapa
                    # ----------------------------------------

                    salvar_csv(
                        pacotes
                    )


                    # ----------------------------------------
                    # Limpa mapa
                    # ----------------------------------------

                    limpar_mapa(
                        pacotes
                    )


                    # Reinicia contador
                    contador[0] = 0


                    print(
                        "\nMapa eBPF limpo."
                    )

                    print(
                        "Aguardando próxima transmissão...\n"
                    )


                    ultima_quantidade = 0

                    ultima_atividade = time.time()

                    em_transmissao = False


            else:

                print(
                    "\rAguardando transmissão...",
                    end="",
                    flush=True
                )


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