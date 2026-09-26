#!/usr/bin/env python3

from bcc import BPF
import time
import sys
import csv
import os
import socket
import struct

# CONFIGURAÇÕES
INTERFACE = "eth1"
TIMEOUT_INATIVIDADE = 5.0
ARQUIVO_CSV = "pacotes_h264.csv"

TYPE_IDR = 0
TYPE_NON_IDR = 1

# ESTADO GLOBAL
idr_count = 0
non_idr_count = 0
numero_pacote = 0
ultima_atividade = time.time()
em_transmissao = False
repeticao = 1

csv_file_handle = None
csv_writer = None


def anexar_xdp(bpf, fn, interface):
    try:
        bpf.attach_xdp(interface, fn, 0)
    except Exception as e:
        print(f"Erro ao anexar XDP: {e}")
        sys.exit(1)


def remover_xdp(bpf, interface):
    try:
        bpf.remove_xdp(interface, 0)
    except Exception:
        pass


def ip_para_string(ip):
    # "!I" garante o correto desembalamento do Byte Order de Rede
    return socket.inet_ntoa(struct.pack("!I", ip))


def preparar_csv():
    global csv_file_handle, csv_writer
    
    arquivo_existe = os.path.exists(ARQUIVO_CSV)
    
    # Abre o arquivo em modo append ("a") e mantém aberto para alta performance
    csv_file_handle = open(ARQUIVO_CSV, mode="a", newline="", encoding="utf-8")
    csv_writer = csv.writer(csv_file_handle)

    if not arquivo_existe:
        csv_writer.writerow([
            "Rodada", "Pacote", "Tipo", "Timestamp_kernel_ns",
            "IP_origem", "IP_destino", "Porta_origem", "Porta_destino",
            "RTP_sequence", "RTP_timestamp", "RTP_marker",
            "NAL_type", "FU_start", "FU_end"
        ])
        csv_file_handle.flush()


def registrar_pacote(event):
    global idr_count, non_idr_count, numero_pacote
    global ultima_atividade, em_transmissao

    if event.type == TYPE_IDR:
        tipo = "I"
        idr_count += 1
    elif event.type == TYPE_NON_IDR:
        tipo = "Non-I"
        non_idr_count += 1
    else:
        return

    numero_pacote += 1
    ultima_atividade = time.time()
    em_transmissao = True

    ip_origem = ip_para_string(event.src_ip)
    ip_destino = ip_para_string(event.dst_ip)

    porta_origem = socket.ntohs(event.src_port)
    porta_destino = socket.ntohs(event.dst_port)

    # Escreve usando o handle persistentemente aberto
    csv_writer.writerow([
        repeticao,
        numero_pacote,
        tipo,
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


def callback_evento(cpu, data, size):
    event = b["events"].event(data)
    registrar_pacote(event)


def registrar_resumo():
    if csv_file_handle:
        csv_file_handle.flush()  # Garante escrita no disco ao final do bloco/rodada

    print("\n\n==============================")
    print(f" [FIM DA RODADA {repeticao}]")
    print("==============================")
    print(f" Pacotes I     : {idr_count}")
    print(f" Pacotes Non-I : {non_idr_count}")
    print(f" Total         : {idr_count + non_idr_count}")
    print(f" Tabela        : {ARQUIVO_CSV}")
    print("==============================\n")


def resetar_contadores():
    global idr_count, non_idr_count, numero_pacote
    idr_count = 0
    non_idr_count = 0
    numero_pacote = 0


def main():
    global b, repeticao, em_transmissao, ultima_atividade

    preparar_csv()

    try:
        b = BPF(src_file="c.bpf.c")
        fn = b.load_func("ebpf_xdp", BPF.XDP)
        anexar_xdp(b, fn, INTERFACE)

        print(f"XDP carregado na interface {INTERFACE}")
        print(f"Tabela sendo salva em: {ARQUIVO_CSV}")
        print("Aguardando tráfego H.264...\n")

        b["events"].open_perf_buffer(callback_evento)

        while True:
            b.perf_buffer_poll(timeout=100)
            agora = time.time()

            if em_transmissao:
                tempo_sem_pacotes = agora - ultima_atividade

                print(
                    f"\r[Rodada {repeticao}] "
                    f"I: {idr_count} | Non-I: {non_idr_count} | "
                    f"Total: {idr_count + non_idr_count} | "
                    f"Inativo há: {tempo_sem_pacotes:.1f}s",
                    end="",
                    flush=True
                )

                if tempo_sem_pacotes >= TIMEOUT_INATIVIDADE:
                    registrar_resumo()
                    repeticao += 1
                    resetar_contadores()
                    em_transmissao = False
                    ultima_atividade = agora
            else:
                print(
                    f"\r[Aguardando Rodada {repeticao}] "
                    f"Esperando o FFmpeg iniciar o envio...",
                    end="",
                    flush=True
                )

    except KeyboardInterrupt:
        print("\n\nEncerrando e removendo XDP...")
        remover_xdp(b, INTERFACE)
        if csv_file_handle:
            csv_file_handle.close()
        sys.exit(0)

    except Exception as e:
        print(f"\n\nErro: {e}")
        remover_xdp(b, INTERFACE)
        if csv_file_handle:
            csv_file_handle.close()
        sys.exit(1)


if __name__ == "__main__":
    main()