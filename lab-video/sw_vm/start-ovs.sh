sudo apt update

sleep 5

sudo apt upgrade

sudo apt install openvswitch-switch -y

sleep 2


sudo ovs-vsctl add-br br0

sudo ovs-vsctl add-port br0 eth1
sudo ovs-vsctl add-port br0 eth2

echo "para conferir use: sudo ovs-vsctl show"