Vagrant.configure("2") do |config|

  config.ssh.forward_x11 = true

  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 2048
    libvirt.cpus = 2
  end

  config.vm.define "vm1" do |client|
    client.vm.box = "generic/ubuntu2204"
    client.vm.hostname = "vm1"
    client.vm.network "private_network", ip: "10.0.0.1", libvirt__network_name: "net-kvm"

    client.vm.provider :libvirt do |lv|
      lv.memory = 2048
      lv.cpus = 2
    end

    client.vm.provision "shell", inline: <<-SHELL
      apt update
      apt install -y \
      git \
      iproute2 \
      iperf3 \
      hping3 \
      tcpdump \
      net-tools \
      curl \
      python3 \
      python3-pip \
      vim

      # pip3 install scapy
    SHELL
  end

# ----------------------------------------------------------------------------
  
  config.vm.define "vm2" do |server|
    server.vm.box = "generic/ubuntu2204"
    server.vm.hostname = "vm2"

    # server.vm.synced_folder "./logs", "/home/vagrant/logs"

    server.vm.network "private_network", ip: "10.0.0.2", libvirt__network_name: "net-kvm"

    server.vm.provider :libvirt do |lv|
      lv.memory = 2048
      lv.cpus = 2
    end

    server.vm.provision "shell", inline: <<-SHELL
      apt update

      apt install -y \
      git build-essential clang llvm python3 python3-pip python3-bpfcc bpfcc-tools libbpfcc-dev linux-headers-$(uname -r) iproute2 tcpdump \
      ethtool vim xauth
    SHELL
  end

end
