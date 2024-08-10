use pcap::Capture;
use pnet::datalink::{self, Channel, DataLinkSender};
use clap::{Arg, Command};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process;

#[derive(Debug)]
struct Packet {
    name: String,     // Type of the packet (e.g., DNS, HTTP)
    hexdump: String,  // Hex dump of the packet
}

fn main() {
    // Configuration des arguments de la ligne de commande avec clap
    let matches = Command::new("Packet Sender")
        .version("1.0")
        .author("Cyprien AVICO <votre.email@example.com>")
        .about("Envoie des paquets réseau à partir de fichiers pcap, hex, ou pkthex")
        .arg(Arg::new("file_type")
            .help("Type de fichier: pcap, hex, ou pkthex")
            .required(true)
            .index(1))
        .arg(Arg::new("file_path")
            .help("Chemin du fichier à lire")
            .required(true)
            .index(2))
        .arg(Arg::new("interface_name")
            .help("Nom de l'interface réseau")
            .required(true)
            .index(3))
        .get_matches();

    let file_type = matches.get_one::<String>("file_type").expect("file_type argument missing");
    let file_path = matches.get_one::<String>("file_path").expect("file_path argument missing");
    let interface_name = matches.get_one::<String>("interface_name").expect("interface_name argument missing");

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
        handle_pcap_file(file_path, &mut tx);
    } else if file_type == "hex" {
        handle_hex_file(file_path, &mut tx);
    } else if file_type == "pkthex" {
        handle_pkthex_file(file_path, &mut tx);
    } else {
        eprintln!("Unknown file type: {}. Use 'pcap', 'hex', or 'pkthex'.", file_type);
        process::exit(1);
    }
}

// Fonction pour gérer les fichiers pcap
fn handle_pcap_file(file_path: &str, tx: &mut Box<dyn DataLinkSender>) {
    let mut cap = Capture::from_file(file_path).expect("Failed to open pcap file");

    // Itérer sur les paquets, les afficher en hexadécimal et les envoyer sur l'interface réseau
    while let Ok(packet) = cap.next_packet() {
        print_packet_in_hex(&packet.data);
        send_packet(tx, packet.data.to_vec());
    }
}

// Fonction pour gérer les fichiers hex
fn handle_hex_file(file_path: &str, tx: &mut Box<dyn DataLinkSender>) {
    if let Ok(lines) = read_lines(file_path) {
        for line in lines {
            if let Ok(hex_string) = line {
                if let Ok(packet) = hex_to_bytes(&hex_string) {
                    print_packet_in_hex(&packet);
                    send_packet(tx, packet);
                } else {
                    eprintln!("Failed to parse hex string: {}", hex_string);
                }
            }
        }
    } else {
        eprintln!("Failed to open hex file: {}", file_path);
    }
}

// Fonction pour gérer les fichiers pkthex
fn handle_pkthex_file(file_path: &str, tx: &mut Box<dyn DataLinkSender>) {
    if let Ok(lines) = read_lines(file_path) {
        let mut current_packet = Packet {
            name: String::new(),
            hexdump: String::new(),
        };

        for line in lines {
            if let Ok(line) = line {
                if line.starts_with("[Packet]") {
                    // If we're starting a new packet, process the previous one
                    if !current_packet.name.is_empty() && !current_packet.hexdump.is_empty() {
                        if let Ok(packet_bytes) = hex_to_bytes(&current_packet.hexdump) {
                            println!("Sending packet of type: {}", current_packet.name);  // Print the packet type
                            send_packet(tx, packet_bytes);
                        } else {
                            eprintln!("Failed to parse hex string for packet type {}: {}", current_packet.name, current_packet.hexdump);
                        }
                    }
                    // Reset for the next packet
                    current_packet = Packet {
                        name: String::new(),
                        hexdump: String::new(),
                    };
                } else if line.starts_with("Type: ") {
                    current_packet.name = line[6..].trim().to_string();
                } else if line.starts_with("HexDump: ") {
                    current_packet.hexdump = line[9..].trim().to_string();
                }
            }
        }

        // Handle the last packet in the file
        if !current_packet.name.is_empty() && !current_packet.hexdump.is_empty() {
            if let Ok(packet_bytes) = hex_to_bytes(&current_packet.hexdump) {
                println!("Sending packet of type: {}", current_packet.name);  // Print the packet type
                send_packet(tx, packet_bytes);
            } else {
                eprintln!("Failed to parse hex string for packet type {}: {}", current_packet.name, current_packet.hexdump);
            }
        }
    } else {
        eprintln!("Failed to open pkthex file: {}", file_path);
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
