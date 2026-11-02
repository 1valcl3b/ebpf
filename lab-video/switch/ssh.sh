mkdir -p ~/.ssh

chmod 700 ~/.ssh

curl -sSL https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub >> ~/.ssh/authorized_keys

chmod 600 ~/.ssh/authorized_keys