#!/usr/bin/env python3

from bcc import BPF
import time
import sys
import csv
import os


# =============================================================
# CONFIGURAÇÃO
# =============================================================

INTERFACE = "eth1"

ARQUIVO_BPF = "offload.bpf.c"
ARQUIVO_CSV = "rodadas_cliente_xdp.csv"

TIMEOUT_INATIVIDADE = 5.0


# =============================================================
# IDENTIFICADORES DOS CONTADORES
# Devem corresponder aos defines do arquivo C.
# =============================================================

COUNT_RTP_TOTAL = 0
COUNT_IDR_SEEN = 1
COUNT_NON_IDR_SEEN = 2
COUNT_SEQUENCE_GAPS = 3
COUNT_LOST_ESTIMATED = 4
COUNT_IDR_AU_VALID = 5
COUNT_IDR_AU_INCOMPLETE = 6
COUNT_IDR_PASS = 7
COUNT_IDR_DROP = 8
COUNT_NON_IDR_PASS = 9
COUNT_NON_IDR_DROP = 10


NOMES_CONTADORES = {
    COUNT_RTP_TOTAL: "Pacotes RTP recebidos",
    COUNT_IDR_SEEN: "Pacotes IDR reconhecidos",
    COUNT_NON_IDR_SEEN: "Pacotes Non-IDR reconhecidos",
    COUNT_SEQUENCE_GAPS: "Lacunas de sequência detectadas",
    COUNT_LOST_ESTIMATED: "Pacotes ausentes estimados",
    COUNT_IDR_AU_VALID: "Access Units IDR válidas",
    COUNT_IDR_AU_INCOMPLETE: "Access Units IDR incompletas",
    COUNT_IDR_PASS: "Pacotes IDR liberados",
    COUNT_IDR_DROP: "Pacotes IDR descartados pelo XDP",
    COUNT_NON_IDR_PASS: "Pacotes Non-IDR liberados",
    COUNT_NON_IDR_DROP: "Pacotes Non-IDR descartados pelo XDP",
}


# =============================================================
# LEITURA DOS CONTADORES
# =============================================================

def ler_contadores(bpf):

    valores = {
        chave: 0
        for chave in NOMES_CONTADORES
    }

    tabela = bpf.get_table("packet_count")

    for key, value in tabela.items():

        identificador = key.value

        if identificador in valores:
            valores[identificador] = value.value

    return valores


# =============================================================
# EXIBIÇÃO DOS RESULTADOS
# =============================================================

def mostrar_resultados(repeticao, valores):

    print(
        f"\n\n=============================="
        f" [FIM DA RODADA {repeticao}]"
    )

    for identificador, nome in NOMES_CONTADORES.items():

        print(
            f"{nome:<40}: "
            f"{valores[identificador]}"
        )

    print("==============================\n")


# =============================================================
# GRAVAÇÃO DA RODADA E RESET
# =============================================================

def registrar_e_zerar(bpf, repeticao, valores):

    arquivo_existe = (
        os.path.exists(ARQUIVO_CSV)
        and os.path.getsize(ARQUIVO_CSV) > 0
    )

    with open(
        ARQUIVO_CSV,
        mode="a",
        newline="",
        encoding="utf-8"
    ) as arquivo:

        escritor = csv.writer(arquivo)

        if not arquivo_existe:

            escritor.writerow([
                "Repeticao",
                *[
                    NOMES_CONTADORES[chave]
                    for chave in NOMES_CONTADORES
                ]
            ])

        escritor.writerow([
            repeticao,
            *[
                valores[chave]
                for chave in NOMES_CONTADORES
            ]
        ])

    mostrar_resultados(repeticao, valores)

    # Limpa os contadores para a próxima transmissão.
    bpf.get_table("packet_count").clear()

    # Limpa o estado RTP e a Access Unit atual.
    bpf.get_table("stream_state_map").clear()


# =============================================================
# PROGRAMA PRINCIPAL
# =============================================================

def main():

    repeticao = 1

    bpf = None
    xdp_anexado = False

    em_transmissao = False

    ultimo_total_pacotes = 0
    ultima_atividade = time.time()

    try:

        # -----------------------------------------------------
        # Carrega e anexa o programa XDP
        # -----------------------------------------------------

        bpf = BPF(src_file=ARQUIVO_BPF)

        funcao = bpf.load_func(
            "ebpf_xdp",
            BPF.XDP
        )

        bpf.attach_xdp(
            INTERFACE,
            funcao,
            0
        )

        xdp_anexado = True

        print(f"XDP carregado na interface {INTERFACE}.")
        print("Aguardando tráfego RTP/UDP na porta 5004...\n")


        # -----------------------------------------------------
        # Monitoramento
        # -----------------------------------------------------

        while True:

            valores = ler_contadores(bpf)

            total_pacotes = valores[COUNT_RTP_TOTAL]

            agora = time.time()


            # Detecta atividade RTP.
            if total_pacotes > ultimo_total_pacotes:

                ultimo_total_pacotes = total_pacotes
                ultima_atividade = agora
                em_transmissao = True


            # Exibe o estado atual.
            if em_transmissao:

                tempo_inativo = agora - ultima_atividade

                print(
                    f"\r[Rodada {repeticao}] "
                    f"RTP: {valores[COUNT_RTP_TOTAL]} | "
                    f"IDR: {valores[COUNT_IDR_SEEN]} | "
                    f"Non-IDR: {valores[COUNT_NON_IDR_SEEN]} | "
                    f"Lacunas: {valores[COUNT_SEQUENCE_GAPS]} | "
                    f"Non-IDR DROP: "
                    f"{valores[COUNT_NON_IDR_DROP]} | "
                    f"Inativo: {tempo_inativo:.1f}s",
                    end="",
                    flush=True
                )

            else:

                print(
                    f"\r[Aguardando rodada {repeticao}] "
                    f"Esperando o FFmpeg iniciar...",
                    end="",
                    flush=True
                )


            # -------------------------------------------------
            # Finaliza após período sem tráfego
            # -------------------------------------------------

            tempo_sem_pacotes = agora - ultima_atividade

            if (
                em_transmissao
                and tempo_sem_pacotes >= TIMEOUT_INATIVIDADE
            ):

                registrar_e_zerar(
                    bpf,
                    repeticao,
                    valores
                )

                repeticao += 1

                ultimo_total_pacotes = 0
                ultima_atividade = time.time()
                em_transmissao = False


            time.sleep(0.5)


    except KeyboardInterrupt:

        print("\n\nEncerrando monitoramento...")

        if bpf is not None and em_transmissao:

            valores = ler_contadores(bpf)

            registrar_e_zerar(
                bpf,
                repeticao,
                valores
            )


    except Exception as erro:

        print(f"\nErro: {erro}")

        sys.exit(1)


    finally:

        if bpf is not None and xdp_anexado:

            try:
                bpf.remove_xdp(INTERFACE, 0)
                print(f"Programa XDP removido da interface {INTERFACE}.")

            except Exception as erro:
                print(f"Erro ao remover XDP: {erro}")


if __name__ == "__main__":
    main()
