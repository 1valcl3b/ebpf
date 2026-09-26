#!/bin/bash

BASHRC_FILE="$HOME/.bashrc"




sudo apt update -y 

sleep 5

sudo apt upgrade -y

sudo apt install openvswitch-switch -y

sleep 5

sudo apt install -y git build-essential clang llvm python3 python3-pip python3-bpfcc bpfcc-tools libbpfcc-dev linux-headers-$(uname -r) iproute2 tcpdump ethtool vim xauth ffmpeg python3-pyroute2 


sleep 2


sudo ovs-vsctl add-br br0

sudo ovs-vsctl add-port br0 eth1
sudo ovs-vsctl add-port br0 eth2

echo "para conferir use: sudo ovs-vsctl show"

cat << 'EOF' >> "$BASHRC_FILE"
alias ..='cd ..'
alias c='clear'
alias ks='ls -la'
alias desligar="shutdown now"
EOF

source "$BASHRC_FILE"