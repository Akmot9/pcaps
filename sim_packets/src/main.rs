extern crate pcap;
extern crate pnet;

use pcap::Capture;
use pnet::datalink::{self, Channel, DataLinkSender};
use std::env;
use std::process;

fn main() {
    // Récupérer le chemin du fichier pcap et l'interface réseau depuis les arguments de la ligne de commande
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <pcap file> <network interface>", args[0]);
        process::exit(1);
    }
    let pcap_file = &args[1];
    let interface_name = &args[2];

    // Ouvrir le fichier pcap
    let mut cap = Capture::from_file(pcap_file).expect("Failed to open pcap file");

    // Trouver l'interface réseau
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| iface.name == *interface_name).expect("Failed to find the specified interface");

    // Configurer l'émetteur de paquets
    let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    // Itérer sur les paquets, les afficher en hexadécimal et les envoyer sur l'interface réseau
    while let Ok(packet) = cap.next_packet() {
        print_packet_in_hex(&packet.data);
        send_packet(&mut tx, &packet.data);
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
fn send_packet(tx: &mut Box<dyn DataLinkSender>, data: &[u8]) {
    let _ = tx.build_and_send(1, data.len(), &mut |packet| {
        packet.copy_from_slice(data);
    }).expect("Failed to send packet");
}
