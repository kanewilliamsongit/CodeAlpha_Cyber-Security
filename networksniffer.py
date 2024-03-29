from scapy.all import Ether, sniff, TCP, UDP

def packet_callback(packet):
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        proto = packet[Ether].type
        print("\nEthernet Frame:")
        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}, Protocol: {hex(proto)}")

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP Packet: Source Port: {src_port}, Destination Port: {dst_port}")

    if UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"UDP Packet: Source Port: {src_port}, Destination Port: {dst_port}")

def main():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
