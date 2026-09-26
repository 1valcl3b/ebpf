#!/usr/bin/env python3

from bcc import BPF

import time
import sys
import csv
import os
import socket
import struct
import ctypes


# =========================================================
# CONFIGURAÇÃO
# =========================================================

INTERFACE = "eth1"

TIMEOUT_INATIVIDADE = 5.0

ARQUIVO_CSV = "pacotes_I.csv"


# =========================================================
# ESTRUTURA DO EVENTO
#
# Deve corresponder exatamente à estrutura
# struct packet_event do c.bpf.c
# =========================================================

class PacketEvent(ctypes.Structure):

    _fields_ = [

        # __u32
        ("type", ctypes.c_uint32),

        # __u32
        ("src_ip", ctypes.c_uint32),

        # __u32
        ("dst_ip", ctypes.c_uint32),

        # __u16
        ("src_port", ctypes.c_uint16),

        # __u16
        ("dst_port", ctypes.c_uint16),

        # __u16
        ("rtp_seq", ctypes.c_uint16),

        # __u32
        ("rtp_timestamp", ctypes.c_uint32),

        # __u8
        ("rtp_marker", ctypes.c_uint8),

        # __u8
        ("nal_type", ctypes.c_uint8),

        # __u8
        ("fu_start", ctypes.c_uint8),

        # __u8
        ("fu_end", ctypes.c_uint8),

        # __u64
        ("timestamp_ns", ctypes.c_uint64),
    ]


# =========================================================
# CONTADOR
# =========================================================

pacotes_i = 0

numero_pacote = 0

repeticao = 1

ultima_atividade = time.time()

em_transmissao = False


# =========================================================
# ANEXAR XDP
# =========================================================

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


# =========================================================
# REMOVER XDP
# =========================================================

def remover_xdp(bpf, interface):

    try:

        bpf.remove_xdp(
            interface,
            0
        )

    except:

        pass


# =========================================================
# CONVERTER IP
# =========================================================

def ip_para_string(ip):

    return socket.inet_ntoa(
        struct.pack(
            "I",
            ip
        )
    )


# =========================================================
# PREPARAR CSV
# =========================================================

def preparar_csv():

    arquivo_existe = os.path.exists(
        ARQUIVO_CSV
    )


    if not arquivo_existe:

        with open(
            ARQUIVO_CSV,
            mode="w",
            newline="",
            encoding="utf-8"
        ) as f:

            escritor = csv.writer(f)


            escritor.writerow([
                "Rodada",
                "Pacote_I",
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


# =========================================================
# REGISTRAR PACOTE I
# =========================================================

def registrar_pacote(event):

    global pacotes_i
    global numero_pacote
    global ultima_atividade
    global em_transmissao


    # =====================================================
    # CONTADOR
    # =====================================================

    pacotes_i += 1

    numero_pacote += 1


    # =====================================================
    # ATUALIZA ATIVIDADE
    # =====================================================

    ultima_atividade = time.time()

    em_transmissao = True


    # =====================================================
    # IP
    # =====================================================

    ip_origem = ip_para_string(
        event.src_ip
    )

    ip_destino = ip_para_string(
        event.dst_ip
    )


    # =====================================================
    # PORTAS
    # =====================================================

    porta_origem = socket.ntohs(
        event.src_port
    )

    porta_destino = socket.ntohs(
        event.dst_port
    )


    # =====================================================
    # GRAVA NO CSV
    # =====================================================

    with open(
        ARQUIVO_CSV,
        mode="a",
        newline="",
        encoding="utf-8"
    ) as f:

        escritor = csv.writer(f)


        escritor.writerow([

            repeticao,

            numero_pacote,

            event.timestamp_ns,

            ip_origem,

            ip_destino,

            porta_origem,

            porta_destino,

            event.rtp_seq,

            event.rtp_timestamp,

            event.rtp_marker,

            event.nal_type,

            event.fu_start,

            event.fu_end

        ])


# =========================================================
# CALLBACK PERF BUFFER
# =========================================================

def callback_evento(cpu, data, size):

    # data é um endereço de memória.
    #
    # Converte esse endereço para PacketEvent.

    event_ptr = ctypes.cast(
        data,
        ctypes.POINTER(PacketEvent)
    )


    event = event_ptr.contents


    registrar_pacote(
        event
    )


# =========================================================
# RESUMO
# =========================================================

def registrar_resumo():

    print("\n\n")

    print("==============================")

    print(
        f"[FIM DA RODADA {repeticao}]"
    )

    print("==============================")

    print(
        f"Pacotes I gravados: {pacotes_i}"
    )

    print(
        f"Arquivo: {ARQUIVO_CSV}"
    )

    print("==============================")

    print()


# =========================================================
# RESET
# =========================================================

def resetar_contadores():

    global pacotes_i
    global numero_pacote


    pacotes_i = 0

    numero_pacote = 0


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    preparar_csv()


    try:

        # =================================================
        # CARREGA eBPF
        # =================================================

        b = BPF(
            src_file="c.bpf.c"
        )


        # =================================================
        # CARREGA XDP
        # =================================================

        fn = b.load_func(
            "ebpf_xdp",
            BPF.XDP
        )


        # =================================================
        # ANEXA
        # =================================================

        anexar_xdp(
            b,
            fn,
            INTERFACE
        )


        print(
            f"XDP carregado na interface {INTERFACE}"
        )

        print(
            f"Somente pacotes I serão salvos em: "
            f"{ARQUIVO_CSV}"
        )

        print(
            "Aguardando tráfego H.264...\n"
        )


        # =================================================
        # PERF BUFFER
        # =================================================

        b["events"].open_perf_buffer(
            callback_evento
        )


        # =================================================
        # LOOP
        # =================================================

        while True:

            b.perf_buffer_poll(
                timeout=100
            )


            agora = time.time()


            # =================================================
            # TRANSMISSÃO
            # =================================================

            if em_transmissao:

                tempo_sem_pacotes = (
                    agora - ultima_atividade
                )


                print(
                    f"\r"
                    f"[Rodada {repeticao}] "
                    f"Pacotes I: {pacotes_i} | "
                    f"Inativo há: "
                    f"{tempo_sem_pacotes:.1f}s",
                    end="",
                    flush=True
                )


                # =================================================
                # FIM DA TRANSMISSÃO
                # =================================================

                if (
                    tempo_sem_pacotes
                    >= TIMEOUT_INATIVIDADE
                ):

                    registrar_resumo()


                    repeticao += 1


                    resetar_contadores()


                    em_transmissao = False


                    ultima_atividade = agora


            # =================================================
            # AGUARDANDO
            # =================================================

            else:

                print(
                    f"\r"
                    f"[Aguardando Rodada {repeticao}] "
                    f"Esperando o FFmpeg iniciar o envio...",
                    end="",
                    flush=True
                )


    # =====================================================
    # CTRL+C
    # =====================================================

    except KeyboardInterrupt:

        print(
            "\n\nEncerrando e removendo XDP..."
        )


        remover_xdp(
            b,
            INTERFACE
        )


        sys.exit(0)


    # =====================================================
    # ERRO
    # =====================================================

    except Exception as e:

        print(
            "\n\nErro:"
        )

        print(e)


        try:

            remover_xdp(
                b,
                INTERFACE
            )

        except:

            pass


        sys.exit(1)