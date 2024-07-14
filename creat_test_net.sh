#!/bin/bash

# Vérifier si le script est exécuté avec des privilèges root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Création d'une paire d'interfaces veth
sudo ip link add veth0 type veth peer name veth1

# Attribution des adresses IP aux interfaces veth
sudo ip addr add 192.168.10.1/24 dev veth0
sudo ip addr add 192.168.10.2/24 dev veth1

# Activation des interfaces veth
sudo ip link set veth0 up
sudo ip link set veth1 up

# Vérification de la configuration
ip addr show veth0
ip addr show veth1

echo "Paire d'interfaces veth configurée avec succès."
