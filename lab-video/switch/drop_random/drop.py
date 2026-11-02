#!/usr/bin/env python3

from bcc import BPF

import ctypes
import csv
import os
import random
import sys
import time


# =============================================================
# CONFIGURAÇÃO
# =============================================================

INTERFACE = "eth1"

ARQUIVO_BPF = "drop-switch.bpf.c"
ARQUIVO_CSV = "resultados_perda_switch.csv"

TIMEOUT_INATIVIDADE = 5.0

NIVEIS_PERDA = [2, 5, 10]


# =============================================================
# IDENTIFICADORES DOS CONTADORES
# Devem corresponder ao arquivo C.
# =============================================================

STAT_UDP_5004 = 0
STAT_IDR_SEEN = 1
STAT_IDR_DROPPED = 2
STAT_IDR_PASSED = 3
STAT_NON_IDR_SEEN = 4

STAT_COUNT = 5


NOMES_CONTADORES = [
    "Pacotes UDP 5004",
    "Pacotes IDR identificados",
    "Pacotes IDR descartados",
    "Pacotes IDR liberados",
    "Pacotes Non-IDR identificados",
]


# =============================================================
# ESCOLHA DO NÍVEL DE PERDA
# =============================================================

def escolher_modo():

    while True:

        print("\nSelecione o modo de perda:")
        print("  2      - Perda aleatória de 2% dos pacotes IDR")
        print("  5      - Perda aleatória de 5% dos pacotes IDR")
        print("  10     - Perda aleatória de 10% dos pacotes IDR")
        print("  random - Alternar os três níveis entre transmissões")

        opcao = input("\nOpção: ").strip().lower()

        if opcao in ("2", "5", "10"):
            return "fixo", int(opcao)

        if opcao == "random":
            return "random", None

        print("Opção inválida. Digite 2, 5, 10 ou random.")


# =============================================================
# SELEÇÃO ALEATÓRIA DOS NÍVEIS ENTRE RODADAS
# =============================================================

class SeletorPerda:

    def __init__(self, modo, nivel_fixo):

        self.modo = modo
        self.nivel_fixo = nivel_fixo

        self.restantes = []
        self.nivel_anterior = None


    def proximo_nivel(self):

        if self.modo == "fixo":
            return self.nivel_fixo


        # Quando todos os níveis do ciclo forem usados,
        # cria outra ordem aleatória.
        if not self.restantes:

            self.restantes = NIVEIS_PERDA.copy()

            random.shuffle(self.restantes)


            # Evita repetir o mesmo nível na fronteira
            # entre dois ciclos, quando possível.
            if (
                self.nivel_anterior is not None
                and self.restantes[0] == self.nivel_anterior
            ):

                self.restantes[0], self.restantes[1] = (
                    self.restantes[1],
                    self.restantes[0]
                )


        nivel = self.restantes.pop(0)

        self.nivel_anterior = nivel

        return nivel


# =============================================================
# CONFIGURA O MAPA DE PERDA NO eBPF
# =============================================================

def configurar_perda(bpf, percentual):

    mapa = bpf["loss_config"]

    chave = ctypes.c_int(0)
    valor = ctypes.c_uint32(percentual)

    mapa[chave] = valor


# =============================================================
# LEITURA DOS CONTADORES
# =============================================================

def ler_contadores(bpf):

    mapa = bpf["stats"]

    valores = []

    for indice in range(STAT_COUNT):

        chave = ctypes.c_int(indice)

        valores.append(mapa[chave].value)

    return valores


# =============================================================
# REINICIALIZA OS CONTADORES
# =============================================================

def zerar_contadores(bpf):

    mapa = bpf["stats"]

    for indice in range(STAT_COUNT):

        chave = ctypes.c_int(indice)
        valor = ctypes.c_ulonglong(0)

        mapa[chave] = valor


# =============================================================
# GRAVA UMA RODADA NO CSV
# =============================================================

def registrar_rodada(
    rodada,
    modo,
    percentual,
    valores
):

    arquivo_existe = (
        os.path.exists(ARQUIVO_CSV)
        and os.path.getsize(ARQUIVO_CSV) > 0
    )


    idr_vistos = valores[STAT_IDR_SEEN]
    idr_descartados = valores[STAT_IDR_DROPPED]

    if idr_vistos > 0:

        perda_observada = (
            idr_descartados / idr_vistos
        ) * 100

    else:

        perda_observada = 0.0


    with open(
        ARQUIVO_CSV,
        mode="a",
        newline="",
        encoding="utf-8"
    ) as arquivo:

        escritor = csv.writer(arquivo)

        if not arquivo_existe:

            escritor.writerow([
                "Rodada",
                "Modo",
                "Perda configurada (%)",
                *NOMES_CONTADORES,
                "Perda IDR observada (%)",
            ])


        escritor.writerow([
            rodada,
            modo,
            percentual,
            *valores,
            round(perda_observada, 3),
        ])


    print(
        f"\n\n========== FIM DA RODADA {rodada} =========="
    )

    print(f"Modo de execução             : {modo}")
    print(f"Perda configurada             : {percentual}%")

    for indice, nome in enumerate(NOMES_CONTADORES):

        print(
            f"{nome:<32}: {valores[indice]}"
        )

    print(
        f"Perda IDR observada           : "
        f"{perda_observada:.3f}%"
    )

    print(f"Resultados registrados em: {ARQUIVO_CSV}")
    print("============================================\n")


# =============================================================
# PROGRAMA PRINCIPAL
# =============================================================

def main():

    modo, nivel_fixo = escolher_modo()

    seletor = SeletorPerda(modo, nivel_fixo)

    nivel_atual = seletor.proximo_nivel()


    print("\nConfiguração selecionada:")
    print(f"Modo: {modo}")
    print(f"Perda desta transmissão: {nivel_atual}%")
    print(f"Interface: {INTERFACE}")


    bpf = None
    xdp_anexado = False

    rodada = 1

    em_transmissao = False

    ultimo_total = 0
    ultima_atividade = time.monotonic()


    try:

        # -----------------------------------------------------
        # Carrega o programa BPF.
        # -----------------------------------------------------

        bpf = BPF(src_file=ARQUIVO_BPF)


        # Define a porcentagem antes de anexar o XDP.
        configurar_perda(bpf, nivel_atual)

        zerar_contadores(bpf)


        # -----------------------------------------------------
        # Anexa XDP na interface do switch.
        # -----------------------------------------------------

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

        print(f"\nXDP anexado em {INTERFACE}.")
        print("Aguardando o FFmpeg iniciar a transmissão...\n")


        # -----------------------------------------------------
        # Monitoramento contínuo.
        # -----------------------------------------------------

        while True:

            valores = ler_contadores(bpf)

            total = valores[STAT_UDP_5004]

            agora = time.monotonic()


            # Detecta o início ou a continuidade do envio.
            if total > ultimo_total:

                if not em_transmissao:

                    em_transmissao = True

                    print(
                        f"\n[Rodada {rodada}] "
                        f"Transmissão iniciada com perda "
                        f"configurada de {nivel_atual}%."
                    )


                ultimo_total = total
                ultima_atividade = agora


            # Mostra progresso durante a transmissão.
            if em_transmissao:

                tempo_inativo = agora - ultima_atividade

                print(
                    f"\rRodada {rodada} | "
                    f"UDP/5004: {valores[STAT_UDP_5004]} | "
                    f"IDR: {valores[STAT_IDR_SEEN]} | "
                    f"IDR DROP: {valores[STAT_IDR_DROPPED]} | "
                    f"Non-IDR: {valores[STAT_NON_IDR_SEEN]} | "
                    f"Inativo: {tempo_inativo:.1f}s",
                    end="",
                    flush=True
                )


            # -------------------------------------------------
            # Finaliza a rodada após 5 segundos sem pacotes.
            # -------------------------------------------------

            tempo_inativo = agora - ultima_atividade

            if (
                em_transmissao
                and tempo_inativo >= TIMEOUT_INATIVIDADE
            ):

                registrar_rodada(
                    rodada,
                    modo,
                    nivel_atual,
                    valores
                )

                zerar_contadores(bpf)

                rodada += 1

                ultimo_total = 0
                ultima_atividade = time.monotonic()
                em_transmissao = False


                # No modo random, seleciona o nível seguinte.
                if modo == "random":

                    nivel_atual = seletor.proximo_nivel()

                    configurar_perda(
                        bpf,
                        nivel_atual
                    )

                    print(
                        f"Próxima transmissão: "
                        f"perda configurada em {nivel_atual}%."
                    )

                else:

                    print(
                        f"Aguardando próxima transmissão "
                        f"com perda de {nivel_atual}%)."
                    )


            time.sleep(0.5)


    except KeyboardInterrupt:

        print("\n\nMonitoramento interrompido pelo usuário.")

        if bpf is not None and em_transmissao:

            valores = ler_contadores(bpf)

            registrar_rodada(
                rodada,
                modo,
                nivel_atual,
                valores
            )


    except Exception as erro:

        print(f"\nErro: {erro}")

        sys.exit(1)


    finally:

        if bpf is not None and xdp_anexado:

            try:

                bpf.remove_xdp(INTERFACE, 0)

                print(
                    f"XDP removido da interface {INTERFACE}."
                )

            except Exception as erro:

                print(f"Erro ao remover XDP: {erro}")


if __name__ == "__main__":
    main()
