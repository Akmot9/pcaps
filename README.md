### README pour le programme d'envoi de paquets

# PacketSender

PacketSender est un programme écrit en Rust qui permet d'envoyer des paquets réseau à partir de fichiers PCAP ou de fichiers contenant des paquets en hexadécimal sur une interface réseau spécifiée.

## Fonctionnalités

- Lecture de fichiers PCAP pour extraire et envoyer des paquets.
- Lecture de fichiers texte contenant des paquets en hexadécimal pour envoyer des paquets.
- Affichage des paquets en hexadécimal avant de les envoyer.
- Envoi des paquets sur une interface réseau spécifiée.

## Prérequis

- Rust et Cargo installés sur votre système.
- Permissions root pour accéder et envoyer des paquets sur les interfaces réseau.

## Installation

1. Clonez le dépôt :
   ```sh
   git clone https://github.com/votre-utilisateur/PacketSender.git
   cd PacketSender
   ```

2. Ajoutez les dépendances dans le fichier `Cargo.toml` si elles ne sont pas déjà présentes :
   ```toml
   [dependencies]
   pnet = "0.27.2"
   pcap = "0.10.0"
   ```

## Utilisation

### Compiler le programme

Pour compiler le programme, utilisez Cargo :
```sh
cargo build --release
```

### Exécuter le programme

#### Utilisation avec un fichier PCAP

Pour envoyer des paquets à partir d'un fichier PCAP :
```sh
git config pull.rebase false
```

#### Utilisation avec un fichier hexadécimal

Pour envoyer des paquets à partir d'un fichier contenant des paquets en hexadécimal :
```sh
sudo cargo run --release -- hex <chemin_du_fichier_hex> <nom_de_l_interface_reseau>
```

### Exemple de fichier hex

Voici un exemple de contenu pour un fichier hex (nommé `packets.hex`), où chaque ligne représente un paquet en hexadécimal :

```plaintext
f405955b584c2cfda160a1830800450000951a0a40004006c85bc0a801144223541ee0c2208d909f366e25a5fa4780184212631b00000101080a285402659f7b2e11f9beb4d9696e7600000000000000000049000000e2dbec340205000000ac8431b22fde4f3e5c0a66fe052cae7592b3f5270d10db716e5e397758e3cb4f050000006683fa7972c4686607a905e36241a97d3ac62da1db252223d67f877da150ab1a
```

### Structure du Code

- `main.rs` : Contient le code principal du programme.

```rust
extern crate pcap;
extern crate pnet;

use pcap::Capture;
use pnet::datalink::{self, Channel, DataLinkSender};
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process;

fn main() {
    // Récupérer le type de fichier, le chemin du fichier et l'interface réseau depuis les arguments de la ligne de commande
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <file type: pcap|hex> <file path> <network interface>", args[0]);
        process::exit(1);
    }
    let file_type = &args[1];
    let file_path = &args[2];
    let interface_name = &args[3];

    // Trouver l'interface réseau
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| iface.name == *interface_name).expect("Failed to find the specified interface");

    // Configurer l'émetteur de paquets
    let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, _rx)) => (tx, _rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    // Traiter le fichier selon son type
    if file_type == "pcap" {
        // Ouvrir le fichier pcap
        let mut cap = Capture::from_file(file_path).expect("Failed to open pcap file");

        // Itérer sur les paquets, les afficher en hexadécimal et les envoyer sur l'interface réseau
        while let Ok(packet) = cap.next_packet() {
            print_packet_in_hex(&packet.data);
            send_packet(&mut tx, packet.data.to_vec());
        }
    } else if file_type == "hex" {
        // Ouvrir le fichier hex
        if let Ok(lines) = read_lines(file_path) {
            for line in lines {
                if let Ok(hex_string) = line {
                    if let Ok(packet) = hex_to_bytes(&hex_string) {
                        print_packet_in_hex(&packet);
                        send_packet(&mut tx, packet);
                    } else {
                        eprintln!("Failed to parse hex string: {}", hex_string);
                    }
                }
            }
        } else {
            eprintln!("Failed to open hex file: {}", file_path);
        }
    } else {
        eprintln!("Unknown file type: {}. Use 'pcap' or 'hex'.", file_type);
        process::exit(1);
    }
}

// Fonction pour afficher un paquet en hexadécimal
fn print_packet_in_hex(data: &[u8]) {
    for byte in data {
        print!("{:02X} ", byte);
    }
    println!();
}

// Fonction pour envoyer un paquet sur l'interface réseau
fn send_packet(tx: &mut Box<dyn DataLinkSender>, data: Vec<u8>) {
    let _ = tx.build_and_send(1, data.len(), &mut |packet| {
        packet.copy_from_slice(&data);
    }).expect("Failed to send packet");
}

// Fonction pour lire les lignes d'un fichier
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

// Fonction pour convertir une chaîne hexadécimale en vecteur d'octets
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
}
```

### Contribuer

1. Forkez le projet
2. Créez votre branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Commitez vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Poussez votre branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

### Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

### Remerciements

- [Rust Programming Language](https://www.rust-lang.org/)
- [pnet crate](https://docs.rs/pnet/)
- [pcap crate](https://docs.rs/pcap/)
