#!/bin/bash

# Vérifier si le script est exécuté avec des privilèges root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Suppression des interfaces veth
sudo ip link delete veth0
sudo ip link delete veth1

echo "Paire d'interfaces veth supprimée avec succès."
