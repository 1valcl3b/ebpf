#!/usr/bin/env bash


DIR_ATUAL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


sudo virsh net-define "$DIR_ATUAL/net-server.xml"
sudo virsh net-define "$DIR_ATUAL/net-client.xml"


sudo virsh net-start net-server
sudo virsh net-start net-client

sudo virsh net-autostart net-server
sudo virsh net-autostart net-client

echo "Redes criadas"
