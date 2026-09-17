#!/bin/bash

PAUSA_ENTRE_RODADAS=10

RODADA=1

while true; do
    echo "=========================================="
    echo " [SERVER] Iniciando Envio - Rodada $RODADA"
    echo "=========================================="

    ffmpeg -re -i videos/video.mp4 -an -c:v copy -f rtp rtp://10.0.0.2:5004 -y 
    echo ""
    echo "[SERVER] Vídeo finalizado. Entrando em silêncio por ${PAUSA_ENTRE_RODADAS}s..."
    
    sleep $PAUSA_ENTRE_RODADAS

    echo "[SERVER] Preparando próxima rodada..."
    echo ""

    RODADA=$((RODADA + 1))
done
