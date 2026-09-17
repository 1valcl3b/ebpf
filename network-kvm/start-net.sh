#!/usr/bin/env bash


DIR_ATUAL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


sudo virsh net-define "$DIR_ATUAL/net-server-p4.xml"
sudo virsh net-define "$DIR_ATUAL/net-client-p4.xml"


sudo virsh net-start net-server-p4
sudo virsh net-start net-client-p4

sudo virsh net-autostart net-server-p4
sudo virsh net-autostart net-client-p4

echo "Redes criadas"
