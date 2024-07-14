from scapy.all import rdpcap, sendp
import sys

def simulate_packets(pcap_file, interface):
    # Lire les paquets du fichier PCAP
    packets = rdpcap(pcap_file)
    
    # Envoyer chaque paquet sur l'interface réseau spécifiée
    for packet in packets:
        sendp(packet, iface=interface)
        print(f"Sent packet: {packet.summary()}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python simulate_packets.py <pcap_file> <interface>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    interface = sys.argv[2]
    
    simulate_packets(pcap_file, interface)
