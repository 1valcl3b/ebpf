#!/usr/bin/env python3
"""Carrega o XDP H.264/RTP e grava eventos de pacotes/AUs em CSV."""

import argparse
import csv
import ctypes
import os
import sys
import time

try:
    from bcc import BPF
except ImportError:
    print("Erro: módulo BCC não encontrado. Instale o pacote python3-bpfcc/BCC.", file=sys.stderr)
    sys.exit(1)


COUNTERS = {
    0: "Pacotes RTP recebidos pelo XDP",
    1: "Pacotes IDR reconhecidos",
    2: "Pacotes Non-IDR reconhecidos",
    3: "Lacunas de sequência detectadas",
    4: "Pacotes ausentes estimados",
    5: "Access Units IDR válidas",
    6: "Access Units IDR incompletas",
    7: "Pacotes IDR liberados",
    8: "Pacotes IDR descartados pelo XDP",
    9: "Pacotes Non-IDR liberados",
    10: "Pacotes Non-IDR descartados pelo XDP",
}

CSV_COLUMNS = [
    "tempo_ns",
    "tipo_evento",
    "seq",
    "rtp_timestamp",
    "au_timestamp",
    "nal_type_rtp",
    "h264_nal_type",
    "classificacao",
    "marker",
    "fu_start",
    "fu_end",
    "gap_detected",
    "lost_estimated",
    "au_broken",
    "waiting_for_idr",
    "acao",
    "status_au",
    "motivo_fechamento_au",
]


def numero(valor):
    """Converte um campo ctypes ou inteiro para int comum."""
    return int(valor.value) if hasattr(valor, "value") else int(valor)


def classificar_h264(h264_type):
    if h264_type == 5:
        return "IDR"
    if h264_type == 1:
        return "NON_IDR"
    if h264_type == 28:
        return "FU_A_SEM_TIPO_INTERNO"
    return "OUTRO"


def ler_contador(tabela, indice):
    try:
        valor = tabela[ctypes.c_uint(indice)]
        return numero(valor)
    except KeyError:
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Registra eventos RTP/H.264 e fechamento de AUs IDR via XDP."
    )
    parser.add_argument(
        "interface",
        help="Interface de rede na qual o XDP será anexado (ex.: q ou eth1).",
    )
    parser.add_argument(
        "--csv",
        default="eventos_au_idr.csv",
        help="Caminho do CSV de eventos (padrão: eventos_au_idr.csv).",
    )
    args = parser.parse_args()

    diretorio = os.path.dirname(os.path.abspath(__file__))
    arquivo_c = os.path.join(diretorio, "offload.bpf.c")
    if not os.path.isfile(arquivo_c):
        print(f"Erro: não encontrei o código C em: {arquivo_c}", file=sys.stderr)
        print("Coloque offload.py e offload.bpf.c no mesmo diretório.", file=sys.stderr)
        return 1

    caminho_csv = os.path.abspath(args.csv)
    os.makedirs(os.path.dirname(caminho_csv), exist_ok=True)

    arquivo_csv = open(caminho_csv, "w", newline="", encoding="utf-8")
    escritor = csv.writer(arquivo_csv)
    escritor.writerow(CSV_COLUMNS)
    arquivo_csv.flush()

    estado = {
        "eventos": 0,
        "eventos_perf_perdidos": 0,
        "ultimo_flush": time.monotonic(),
    }

    bpf = None
    anexado = False

    try:
        print(f"Carregando programa eBPF: {arquivo_c}")
        bpf = BPF(src_file=arquivo_c)
        funcao_xdp = bpf.load_func("ebpf_xdp", BPF.XDP)

        # Cada execução cria mapas novos associados a esta instância do BPF.
        bpf.attach_xdp(args.interface, funcao_xdp, 0)
        anexado = True

        tabela_eventos = bpf["debug_events"]

        def receber_evento(cpu, data, size):
            evento = tabela_eventos.event(data)

            event_type = numero(evento.event_type)
            action = numero(evento.action)
            au_status = numero(evento.au_status)
            motivo_fechamento = numero(evento.au_close_reason)
            h264_type = numero(evento.h264_type)

            tipo_evento = {
                1: "PACOTE",
                2: "AU_IDR_FECHADA",
            }.get(event_type, "DESCONHECIDO")
            acao = {0: "DROP", 1: "PASS", 2: "N/A"}.get(action, "DESCONHECIDA")
            status_au = {
                0: "N/A",
                1: "VALIDA",
                2: "INCOMPLETA",
            }.get(au_status, "DESCONHECIDO")
            motivo_au = {
                0: "N/A",
                1: "MARKER",
                2: "TIMESTAMP_MUDOU_SEM_MARKER",
            }.get(motivo_fechamento, "DESCONHECIDO")

            escritor.writerow([
                numero(evento.tempo_ns),
                tipo_evento,
                numero(evento.seq),
                numero(evento.rtp_timestamp),
                numero(evento.au_timestamp),
                numero(evento.nal_type),
                h264_type,
                classificar_h264(h264_type),
                numero(evento.marker),
                numero(evento.fu_start),
                numero(evento.fu_end),
                numero(evento.gap_detected),
                numero(evento.lost_estimated),
                numero(evento.au_broken),
                numero(evento.waiting_for_idr),
                acao,
                status_au,
                motivo_au,
            ])
            estado["eventos"] += 1

        def avisar_eventos_perdidos(cpu, quantidade):
            estado["eventos_perf_perdidos"] += int(quantidade)
            print(
                f"Aviso: o buffer perf perdeu {quantidade} evento(s) no CPU {cpu}.",
                file=sys.stderr,
            )

        tabela_eventos.open_perf_buffer(
            receber_evento,
            lost_cb=avisar_eventos_perdidos,
            page_cnt=64,
        )

        print(f"XDP anexado à interface: {args.interface}")
        print(f"Arquivo de eventos: {caminho_csv}")
        print("Inicie agora o envio RTP/H.264. Pressione Ctrl+C ao terminar.")

        while True:
            bpf.perf_buffer_poll(timeout=200)
            agora = time.monotonic()
            if agora - estado["ultimo_flush"] >= 1.0:
                arquivo_csv.flush()
                estado["ultimo_flush"] = agora

    except KeyboardInterrupt:
        print("\nInterrupção recebida; finalizando os registros...")
    except Exception as erro:
        print(f"Erro durante a execução: {erro}", file=sys.stderr)
        return 1
    finally:
        if anexado and bpf is not None:
            try:
                bpf.remove_xdp(args.interface, 0)
                print(f"XDP removido da interface {args.interface}.")
            except Exception as erro:
                print(f"Aviso ao remover o XDP: {erro}", file=sys.stderr)

        try:
            arquivo_csv.flush()
            arquivo_csv.close()
        except Exception:
            pass

    print("\n=== RESUMO FINAL DO XDP ===")
    if bpf is not None:
        try:
            tabela_contadores = bpf["packet_count"]
            for indice, descricao in COUNTERS.items():
                print(f"{descricao:<40}: {ler_contador(tabela_contadores, indice)}")
        except Exception as erro:
            print(f"Não foi possível ler os contadores finais: {erro}")

    print(f"Eventos gravados no CSV                 : {estado['eventos']}")
    print(f"Eventos perdidos no buffer perf         : {estado['eventos_perf_perdidos']}")
    print(f"CSV                                    : {caminho_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
