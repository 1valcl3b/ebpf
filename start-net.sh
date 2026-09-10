sudo virsh net-define net-server-p4.xml
sudo virsh net-define net-client-p4.xml

sudo virsh net-start net-server-p4
sudo virsh net-start net-client-p4

sudo virsh net-autostart net-server-p4
sudo virsh net-autostart net-client-p4
