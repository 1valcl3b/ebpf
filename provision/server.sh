apt update 
sleep 2

apt upgrade
sleep 2	

apt install -y git build-essential clang llvm python3 python3-pip python3-bpfcc bpfcc-tools libbpfcc-dev linux-headers-$(uname -r) iproute2 tcpdump \
      ethtool vim xauth ffmpeg python3-pyroute2
