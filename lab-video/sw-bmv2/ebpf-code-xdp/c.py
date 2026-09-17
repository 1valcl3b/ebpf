#!/usr/bin/env python3

from bcc import BPF
import time
import sys
import csv
import os


INTERFACE = "eth1"

TYPE_IDR = 0
TYPE_NON_IDR = 1

TIMEOUT_INATIVIDADE = 5.0


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


def ler_contadores(bpf):

    tabela = bpf.get_table("packet_count")

    idr = 0
    non_idr = 0

    for key, value in tabela.items():

        if key.value == TYPE_IDR:
            idr = value.value

        elif key.value == TYPE_NON_IDR:
            non_idr = value.value

    return idr, non_idr


def registrar_e_zerar(
    bpf,
    repeticao,
    idr,
    non_idr,
    arq_csv="rodadas.csv"
):

    arq_existe = os.path.exists(arq_csv)

    with open(
        arq_csv,
        mode="a",
        newline="",
        encoding="utf-8"
    ) as f:

        e = csv.writer(f)

        if not arq_existe:
            e.writerow([
                "Repeticao",
                "Pacotes I",
                "Pacotes Non-I"
            ])

        e.writerow([
            repeticao,
            idr,
            non_idr
        ])


    print(
        f"\n\n============================== "
        f"[FIM DA RODADA {repeticao}]"
    )

    print(
        f" Pacotes IDR gravados     : {idr}"
    )

    print(
        f" Pacotes Non-IDR gravados : {non_idr}"
    )

    print(
        " Resetando contadores no eBPF "
        "e aguardando próximo envio..."
    )

    print("==============================\n")


    tabela = bpf.get_table("packet_count")

    tabela.clear()


if __name__ == "__main__":

    repeticao = 1

    try:

        b = BPF(
            src_file="c.bpf.c"
        )

        fn = b.load_func(
            "ebpf_xdp",
            BPF.XDP
        )

        anexar_xdp(
            b,
            fn,
            INTERFACE
        )

        print(
            f"XDP carregado na interface {INTERFACE}"
        )

        print(
            "Aguardando tráfego de pacotes...\n"
        )


        ultimo_total_pacotes = 0

        ultima_atividade = time.time()

        em_transmissao = False


        while True:

            idr, non_idr = ler_contadores(b)

            total_pacotes = idr + non_idr

            agora = time.time()


            # Detecta chegada de novos pacotes
            if total_pacotes > ultimo_total_pacotes:

                ultimo_total_pacotes = total_pacotes

                ultima_atividade = agora

                em_transmissao = True


            tempo_sem_pacotes = (
                agora - ultima_atividade
            )


            # Exibe situação atual
            if em_transmissao:

                print(
                    f"\r[Rodada {repeticao}] "
                    f"Em progresso... "
                    f"IDR: {idr} | "
                    f"Non-IDR: {non_idr} | "
                    f"Inativo há: "
                    f"{tempo_sem_pacotes:.1f}s",
                    end=""
                )

            else:

                print(
                    f"\r[Aguardando Rodada {repeticao}] "
                    f"Esperando o FFmpeg iniciar o envio...",
                    end=""
                )


            # Detecta fim da transmissão
            if (
                em_transmissao
                and tempo_sem_pacotes >= TIMEOUT_INATIVIDADE
            ):

                registrar_e_zerar(
                    b,
                    repeticao,
                    idr,
                    non_idr
                )

                repeticao += 1

                ultimo_total_pacotes = 0

                em_transmissao = False


            time.sleep(0.5)


    except KeyboardInterrupt:

        print(
            "\n\nEncerrando e removendo XDP..."
        )

        remover_xdp(
            b,
            INTERFACE
        )

        sys.exit(0)


    except Exception as e:

        print("\nErro:")
        print(e)

        remover_xdp(
            b,
            INTERFACE
        )

        sys.exit(1)
