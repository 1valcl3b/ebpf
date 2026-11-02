import argparse
import csv
import subprocess
import time
import psutil


def get_pid_by_name(process_name="ffmpeg"):
    try:
       
        output = subprocess.check_output(["pgrep", process_name], text=True)
        
        pids = [int(pid) for pid in output.strip().splitlines() if pid.isdigit()]
        return pids[0] if pids else None
    except (subprocess.CalledProcessError, FileNotFoundError): 
        return None


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
                "mem_percent": mem,
            })

        except psutil.NoSuchProcess:
            print("[ERRO] O processo foi encerrado durante a coleta.")
            break

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["time_sec", "cpu_percent", "mem_percent"]
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[OK] Dados coletados com sucesso! Salvos em: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--pid",
        type=int,
        required=False,
        help="PID do processo (se omitido, busca automaticamente por --name)",
    )

    parser.add_argument(
        "--name",
        type=str,
        default="ffmpeg",
        help="Nome do processo a buscar caso o --pid não seja informado (padrão: ffmpeg)",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=660,
        help="Tempo total de coleta (segundos)",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Intervalo entre amostras (segundos)",
    )

    parser.add_argument(
        "--output",
        type=str,
        default="cpu_mem_processo.csv",
        help="Arquivo CSV de saída",
    )

    args = parser.parse_args()

    pid = args.pid

    # Se o PID não foi informado na linha de comando, tenta buscar via pgrep
    if pid is None:
        print(f"[STATUS] Buscando PID para o processo '{args.name}'...")
        pid = get_pid_by_name(args.name)

        if pid is None:
            print(f"[ERRO] NENHUM processo referente a '{args.name}' foi encontrado pelo pgrep.")
            exit(1)

        print(f"[INFO] PID encontrado automaticamente: {pid}")

    collect_metrics(
        pid,
        args.duration,
        args.interval,
        args.output,
    )