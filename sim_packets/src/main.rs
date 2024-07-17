
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
