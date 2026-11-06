import json
import re
import subprocess
import urllib.request
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ==========================================
# 1. CONFIGURAÇÃO (edite aqui ou passe pela linha de comando)
# ==========================================
PASTA_PADRAO = "/home/cleb/ebpf/vmaf"
VIDEO_REFERENCIA_PADRAO = "bbb_sunflower_2160p_30fps_normal.mp4"        # vídeo original (referência)
VIDEO_AVALIADO_PADRAO1 = "comsolucao.mkv"  # vídeo a ser avaliado
VIDEO_AVALIADO_PADRAO1 = "comsolucao.mkv"


parser = argparse.ArgumentParser(description="Calcula PSNR, SSIM e VMAF entre dois vídeos.")
parser.add_argument("--referencia", default=VIDEO_REFERENCIA_PADRAO, help="Vídeo original (referência)")
parser.add_argument("--avaliado", default=VIDEO_AVALIADO_PADRAO, help="Vídeo degradado a ser avaliado")
parser.add_argument("--pasta", default=PASTA_PADRAO, help="Pasta de trabalho e de saída")
args = parser.parse_args()

output_dir = Path(args.pasta)
output_dir.mkdir(parents=True, exist_ok=True)

def resolver(caminho):
    p = Path(caminho)
    return p if p.is_absolute() else output_dir / p

video_referencia = resolver(args.referencia)
video_avaliado = resolver(args.avaliado)

for v in (video_referencia, video_avaliado):
    if not v.exists():
        raise FileNotFoundError(f"Vídeo não encontrado: {v}")

prefixo = video_avaliado.stem
csv_saida = output_dir / f"metricas_{prefixo}.csv"

# ==========================================
# 2. MODELO VMAF DA NETFLIX
# ==========================================
vmaf_model_path = output_dir / "vmaf_v0.6.1.json"
if not vmaf_model_path.exists():
    print("Baixando o modelo VMAF da Netflix...")
    url = "https://raw.githubusercontent.com/Netflix/vmaf/master/model/vmaf_v0.6.1.json"
    urllib.request.urlretrieve(url, vmaf_model_path)
    print("[OK] Modelo baixado.\n")

# ==========================================
# 3. FUNÇÕES AUXILIARES
# ==========================================
def obter_resolucao(video):
    """Lê largura e altura do vídeo com ffprobe."""
    comando = [
        "ffprobe", "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=width,height", "-of", "json", str(video)
    ]
    resultado = subprocess.run(comando, capture_output=True, text=True)
    if resultado.returncode != 0:
        raise RuntimeError(f"ffprobe falhou em {video.name}:\n{resultado.stderr}")
    stream = json.loads(resultado.stdout)["streams"][0]
    return stream["width"], stream["height"]


def calcular_metricas(referencia, avaliado):
    """Calcula PSNR, SSIM e VMAF quadro a quadro numa única passada do FFmpeg.
    O vídeo avaliado é redimensionado para a resolução da referência."""
    largura, altura = obter_resolucao(referencia)
    print(f"[*] Resolução de referência: {largura}x{altura}")
    print(f"[*] Calculando PSNR, SSIM e VMAF para: {avaliado.name} (isso pode demorar...)")

    log_psnr = f"{prefixo}_psnr.log"
    log_ssim = f"{prefixo}_ssim.log"
    log_vmaf = f"{prefixo}_vmaf.json"

    filtro = (
        f"[0:v]setpts=PTS-STARTPTS,scale={largura}:{altura}:flags=bicubic,format=yuv420p,split=3[d1][d2][d3];"
        f"[1:v]setpts=PTS-STARTPTS,scale={largura}:{altura}:flags=bicubic,format=yuv420p,split=3[r1][r2][r3];"
        f"[d1][r1]psnr=stats_file={log_psnr};"
        f"[d2][r2]ssim=stats_file={log_ssim};"
        f"[d3][r3]libvmaf=model='path={vmaf_model_path.name}':log_fmt=json:log_path={log_vmaf}"
    )
    comando = [
        "ffmpeg", "-y", "-i", str(avaliado), "-i", str(referencia),
        "-lavfi", filtro, "-f", "null", "-"
    ]
    resultado = subprocess.run(comando, capture_output=True, text=True, cwd=output_dir)
    if resultado.returncode != 0:
        raise RuntimeError(f"FFmpeg falhou:\n{resultado.stderr[-2000:]}")

    # PSNR (frames idênticos geram 'inf')
    psnr = []
    with open(output_dir / log_psnr, "r") as f:
        for linha in f:
            m = re.search(r"psnr_avg:(inf|[0-9.]+)", linha)
            if m:
                psnr.append(float(m.group(1)))

    # SSIM
    ssim = []
    with open(output_dir / log_ssim, "r") as f:
        for linha in f:
            m = re.search(r"All:([0-9.]+)", linha)
            if m:
                ssim.append(float(m.group(1)))

    # VMAF
    with open(output_dir / log_vmaf, "r") as f:
        dados = json.load(f)
    vmaf = [frame["metrics"]["vmaf"] for frame in dados.get("frames", [])]

    n = min(len(psnr), len(ssim), len(vmaf))
    if n == 0:
        raise RuntimeError("Nenhum frame foi avaliado. Verifique os vídeos.")
    if len({len(psnr), len(ssim), len(vmaf)}) > 1:
        print(f"[AVISO] Contagens diferentes (PSNR={len(psnr)}, SSIM={len(ssim)}, "
              f"VMAF={len(vmaf)}). Usando os primeiros {n} frames.")

    df = pd.DataFrame({
        "Frame": np.arange(1, n + 1),
        "PSNR": psnr[:n],
        "SSIM": ssim[:n],
        "VMAF": vmaf[:n],
    })
    return df

# ==========================================
# 4. EXECUÇÃO E CRIAÇÃO DO CSV
# ==========================================
df = calcular_metricas(video_referencia, video_avaliado)

frames_psnr_inf = int(np.isinf(df["PSNR"]).sum())
df["PSNR"] = df["PSNR"].replace([np.inf, -np.inf], np.nan)

df.to_csv(csv_saida, index=False)
print(f"[OK] CSV criado: {csv_saida}")

# ==========================================
# 5. CONFIGURAÇÕES VISUAIS DOS GRÁFICOS
# ==========================================
COR = "#0072B2"  # azul Okabe-Ito
rotulo = video_avaliado.stem

def calcular_cdf(dados):
    x = np.sort(dados.dropna())
    y = np.arange(1, len(x) + 1) / len(x)
    return x, y

def aplicar_estilo_eixo(ax, titulo_x, loc_legenda="upper left"):
    ax.set_ylabel("CDF", fontsize=50, fontweight="bold")
    ax.set_xlabel(titulo_x, fontsize=50, fontweight="bold")
    ax.grid(True, linestyle="dotted")
    ax.legend(prop={"size": 40, "weight": "bold"}, loc=loc_legenda)
    ax.tick_params(axis="both", which="major", labelsize=40, width=2)
    for tick in ax.get_xticklabels() + ax.get_yticklabels():
        tick.set_fontweight("bold")

def plotar_cdf(coluna, titulo_x, nome_arquivo, xlim=None):
    fig, ax = plt.subplots(figsize=(15, 10))
    x, y = calcular_cdf(df[coluna])
    ax.plot(x, y, linewidth=4, label=rotulo, color=COR, zorder=3)
    aplicar_estilo_eixo(ax, titulo_x)
    ax.set_ylim(0, 1.05)
    if xlim:
        ax.set_xlim(*xlim)
    plt.tight_layout()
    caminho = output_dir / nome_arquivo
    fig.savefig(caminho, format="pdf", bbox_inches="tight")
    plt.close(fig)
    return caminho

# ==========================================
# 6. PLOTAGEM DAS CDFs
# ==========================================
print("\n[*] Gerando gráficos...")
arq_psnr = plotar_cdf("PSNR", "PSNR (dB)", f"CDF_PSNR_{prefixo}.pdf")
arq_ssim = plotar_cdf("SSIM", "SSIM", f"CDF_SSIM_{prefixo}.pdf",
                      xlim=(max(0, df["SSIM"].min() - 0.05), 1.0))
arq_vmaf = plotar_cdf("VMAF", "VMAF", f"CDF_VMAF_{prefixo}.pdf", xlim=(0, 100))

# ==========================================
# 7. RESUMO ESTATÍSTICO
# ==========================================
def resumo(serie):
    s = serie.dropna()
    return {
        "Média": s.mean(),
        "Desvio padrão": s.std(),
        "Mínimo": s.min(),
        "P5": s.quantile(0.05),
        "P25": s.quantile(0.25),
        "Mediana": s.median(),
        "P75": s.quantile(0.75),
        "P95": s.quantile(0.95),
        "Máximo": s.max(),
    }

tabela = pd.DataFrame({m: resumo(df[m]) for m in ["PSNR", "SSIM", "VMAF"]})

print("\n" + "=" * 60)
print("ARQUIVOS GERADOS")
print("=" * 60)
print(f"[OK] CSV:       {csv_saida}")
print(f"[OK] CDF PSNR:  {arq_psnr}")
print(f"[OK] CDF SSIM:  {arq_ssim}")
print(f"[OK] CDF VMAF:  {arq_vmaf}")

print("\n" + "=" * 60)
print(f"RESUMO ESTATÍSTICO: {video_avaliado.name} vs {video_referencia.name}")
print("=" * 60)
print(f"Frames analisados: {len(df)}")
with pd.option_context("display.float_format", "{:.4f}".format):
    print(tabela)

if frames_psnr_inf:
    print(f"\n[NOTA] {frames_psnr_inf} frame(s) idênticos à referência (PSNR infinito) "
          f"foram excluídos das estatísticas de PSNR.")

vmaf = df["VMAF"]
print("\nDistribuição de qualidade (VMAF):")
print(f"  Excelente (>= 80):  {(vmaf >= 80).mean() * 100:.1f}% dos frames")
print(f"  Boa (60 a 80):      {((vmaf >= 60) & (vmaf < 80)).mean() * 100:.1f}% dos frames")
print(f"  Ruim (< 60):        {(vmaf < 60).mean() * 100:.1f}% dos frames")