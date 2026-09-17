sudo ip link set eth1 up
sudo ip link set eth2 up

sleep 2

echo "Ativando sw bmv2"
sudo simple_switch -i 1@eth1 -i 2@eth2 switch.json


