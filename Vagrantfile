Vagrant.configure("2") do |config|

  # config.ssh.insert_key = false
  
  config.ssh.forward_x11 = true

  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 2048
    libvirt.cpus = 2
    # libvirt.storage_pool_name = "meu_pool"
  end

    config.vm.define "server" do |server|
    server.vm.box = "generic/ubuntu2204"
    server.vm.hostname = "server"

    server.vm.synced_folder "./lab-video/server", "/home/vagrant/server"
    server.vm.synced_folder "./lab-video/videos", "/home/vagrant/videos"

    server.vm.network "private_network",ip: "10.0.0.10", mac: "080027600c50" ,libvirt__network_name: "net-server"

    server.vm.provider :libvirt do |lv|
      lv.memory = 2048
      lv.cpus = 2
    end

    server.vm.provision "shell", path: "provision/server.sh"
    end

# ----------------------------------------------------------------------------

  config.vm.define "client" do |client|
    client.vm.box = "generic/ubuntu2204"
    client.vm.hostname = "client"

    client.vm.synced_folder "./lab-video/client", "/home/vagrant/client"

    client.vm.network "private_network", ip: "10.0.0.2", mac: "0800271de027" ,libvirt__network_name: "net-client"

    client.vm.provider :libvirt do |lv|
      lv.memory = 2048
      lv.cpus = 4
    end

    client.vm.provision "shell", path: "provision/client.sh"
  end

  config.vm.define "sw_vm" do |sw_vm|
    sw_vm.vm.box = "generic/ubuntu2204"
    sw_vm.vm.hostname = "sw-vm"

    sw_vm.vm.synced_folder "./lab-video/switch/", "/home/vagrant/switch"

    sw_vm.vm.network "private_network", libvirt__network_name: "net-server", auto_config: false

    sw_vm.vm.network "private_network", libvirt__network_name: "net-client", auto_config: false

    sw_vm.vm.provider :libvirt do |lv|
      lv.memory = 2048
      lv.cpus = 4   
    end

    sw_vm.vm.provision "shell", path: "provision/sw_vm.sh"
  end
  
end
