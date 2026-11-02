import argparse
import csv
import subprocess
import time


parser = argparse.ArgumentParser(
    description="Receptor de fluxo RTP em tempo real com métricas de FPS."
)
parser.add_argument(
    "--output",
    nargs=2,
    metavar=("CSV_FILE", "VIDEO_FILE"),
    default=["fps.csv", "video.mkv"],
    help="Arquivos de saída no formato: [arquivo.csv] [video.mkv]"
)
parser.add_argument(
    "--sdp",
    default="sdps/bbb_1080p.sdp",
    help="Caminho do arquivo SDP de entrada (padrão: sdps/bbb.sdp)"
)

args = parser.parse_args()


CSV_FILE = args.output[0]
VIDEO_FILE = args.output[1]
SDP = args.sdp


comando = [
    "ffmpeg",
    "-y",
    "-nostats",
    "-progress", "pipe:1",
    "-stats_period", "1",
    "-protocol_whitelist", "file,udp,rtp",
    "-buffer_size", "16777216", 
    "-max_delay", "500000", 
    "-fflags", "+discardcorrupt+nobuffer",
    "-i", SDP,
    "-c:v", "copy",
    VIDEO_FILE
]

# comando = [
#     "ffmpeg",
#     "-y",
#     "-nostats",
#     "-progress", "pipe:1",
#     "-stats_period", "1",

#     # Configurações do socket de entrada RTP/UDP
#     "-protocol_whitelist", "file,udp,rtp",
#     "-buffer_size", "16777216",            # 16 MB de buffer UDP
#     "-max_delay", "500000",                # 500ms de tolerância a jitter no RTP
#     "-fflags", "+discardcorrupt+nobuffer", # Descarta pacotes corrompidos sem acumular atraso
#     "-flags", "+low_delay",

#     "-i", SDP,

#     # Configurações do Codificador H.264 via CPU
#     "-c:v", "libx264",
#     "-preset", "ultrafast",                # Menor consumo possível de CPU por frame
#     "-crf", "23",                         # Fator de qualidade equilibrado
#     "-threads", "0",                       # Distribui a decodificação/codificação por todos os núcleos da CPU

#     VIDEO_FILE
# ]

print(f"Iniciando recepção RTP/H.264 usando SDP: {SDP}")
print("Buffer UDP solicitado: 16777216 bytes")
print("Arquivo CSV de saída:", CSV_FILE)
print("Arquivo de vídeo de saída:", VIDEO_FILE)

inicio = time.monotonic()
ultimo_tempo = inicio
ultimo_frame = 0
dados = {}

processo = subprocess.Popen(comando,stdout=subprocess.PIPE,stderr=None,text=True,bufsize=1)

try:
    with open(CSV_FILE, "w", newline="") as arquivo:
        writer = csv.writer(arquivo)
        writer.writerow([
            "Tempo_s",
            "Quadros_processados",
            "FPS_FFmpeg",
            "FPS_intervalo",
            "Velocidade"
        ])

        for linha in processo.stdout:
            linha = linha.strip()

            if "=" not in linha:
                continue

            chave, valor = linha.split("=", 1)
            dados[chave] = valor

            if chave != "progress":
                continue

            agora = time.monotonic()
            tempo = agora - inicio
            intervalo = agora - ultimo_tempo

            try:
                frames = int(dados.get("frame", "0"))
                fps_ffmpeg = float(dados.get("fps", "0"))
            except ValueError:
                continue

            velocidade = dados.get("speed", "N/A")

            if intervalo > 0:
                fps_intervalo = (
                    (frames - ultimo_frame) / intervalo
                )

                writer.writerow([
                    round(tempo, 2),
                    frames,
                    fps_ffmpeg,
                    round(fps_intervalo, 2),
                    velocidade
                ])

                arquivo.flush()

                print(
                    f"Tempo: {tempo:.1f}s | "
                    f"Quadros: {frames} | "
                    f"FPS intervalo: {fps_intervalo:.2f} | "
                    f"Velocidade: {velocidade}"
                )

            ultimo_tempo = agora
            ultimo_frame = frames

            if valor == "end":
                break

except KeyboardInterrupt:
    print("\nEncerrando captura...")

finally:
    if processo.poll() is None:
        processo.terminate()

    processo.wait()
    print("Captura encerrada.")
    print("CSV salvo em:", CSV_FILE)
    print("Vídeo salvo em:", VIDEO_FILE)