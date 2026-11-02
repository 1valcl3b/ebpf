import psutil
import time
import csv
import argparse

def collect_metrics(duration, interval, output_file):
    data = []
    
    # IMPORTANTE: Faz uma primeira chamada fantasma para inicializar o contador da CPU
    psutil.cpu_percent(interval=None)
    
    start = time.time()
    print(f"[STATUS] Iniciando coleta de métricas por {duration} segundos...")

    while time.time() - start < duration:
        # 1. Espera o intervalo desejado primeiro
        time.sleep(interval)
        
        # 2. Agora o psutil calcula a CPU média usada DURANTE o tempo do sleep acima
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        data.append({
            "time_sec": round(time.time() - start, 2),
            "cpu_percent": cpu,
            "mem_percent": mem
        })

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["time_sec", "cpu_percent", "mem_percent"])
        writer.writeheader()
        writer.writerows(data)

    print(f"[OK] Dados coletados com sucesso! Salvos em: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=30, help="tempo total de coleta (segundos)")
    parser.add_argument("--interval", type=float, default=1.0, help="intervalo entre amostras (segundos)")
    parser.add_argument("--output", type=str, default="cpu_mem.csv", help="arquivo CSV de saída")

    args = parser.parse_args()
    collect_metrics(args.duration, args.interval, args.output)

