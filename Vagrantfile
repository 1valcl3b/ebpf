Vagrant.configure("2") do |config|

  config.ssh.forward_x11 = true

  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 2048
    libvirt.cpus = 2
  end

    config.vm.define "server" do |server|
    server.vm.box = "generic/ubuntu2204"
    server.vm.hostname = "server"

    server.vm.synced_folder "./prat03/codigos", "/home/vagrant/codigos"
    server.vm.synced_folder "./prat03/videos", "/home/vagrant/videos"

    server.vm.network "private_network", ip: "10.0.0.10", libvirt__network_name: "net-kvm"

    server.vm.provider :libvirt do |lv|
      lv.memory = 2048
      lv.cpus = 2
      # lv.management_network_ip = "192.168.121.10"
    end

    server.vm.provision "shell", inline: <<-SHELL
      apt update

      apt install -y \
      git build-essential clang llvm python3 python3-pip python3-bpfcc bpfcc-tools libbpfcc-dev linux-headers-$(uname -r) iproute2 tcpdump \
      ethtool vim xauth ffmpeg
    SHELL
  end

# ----------------------------------------------------------------------------

  config.vm.define "client" do |client|
    client.vm.box = "generic/ubuntu2204"
    client.vm.hostname = "client"

    client.vm.synced_folder "./prat03/codigos", "/home/vagrant/codigos"

    client.vm.network "private_network", ip: "10.0.0.2", libvirt__network_name: "net-kvm"

    client.vm.provider :libvirt do |lv|
      lv.memory = 2048
      lv.cpus = 2
      # lv.management_network_ip = "192.168.121.11"
    end

    client.vm.provision "shell", inline: <<-SHELL
      apt update
      apt install -y \
      git build-essential clang llvm python3 python3-pip python3-bpfcc bpfcc-tools libbpfcc-dev linux-headers-$(uname -r) iproute2 tcpdump \
      iproute2 \
      iperf3 \
      hping3 \
      net-tools \
      curl \
      vim \
      ffmpeg \
      xauth

      # pip3 install scapy
    SHELL
  end
  
end
