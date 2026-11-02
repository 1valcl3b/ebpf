import psutil
import time
import csv
import argparse


def collect_metrics(pid, duration, interval, output_file):
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print(f"[ERRO] Processo com PID {pid} não encontrado.")
        return

    data = []

    # Inicializa o contador de CPU do processo
    process.cpu_percent(interval=None)

    start = time.time()
    print(f"[STATUS] Monitorando o processo PID={pid} por {duration} segundos...")

    while time.time() - start < duration:
        time.sleep(interval)

        try:
            cpu = process.cpu_percent(interval=None)
            mem = process.memory_percent()

            data.append({
                "time_sec": round(time.time() - start, 2),
                "cpu_percent": cpu,
                "mem_percent": mem
            })

        except psutil.NoSuchProcess:
            print("[ERRO] O processo foi encerrado durante a coleta.")
            break

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time_sec", "cpu_percent", "mem_percent"]
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[OK] Dados coletados com sucesso! Salvos em: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--pid",
        type=int,
        required=True,
        help="PID do processo a ser monitorado"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Tempo total de coleta (segundos)"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Intervalo entre amostras (segundos)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="cpu_mem_processo.csv",
        help="Arquivo CSV de saída"
    )

    args = parser.parse_args()

    collect_metrics(
        args.pid,
        args.duration,
        args.interval,
        args.output
    )
