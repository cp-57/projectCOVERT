from scapy.all import sniff, TCP, IP

pre_defined_key = 505

def handle_packet(packet):
    if IP in packet and TCP in packet:
        if packet[IP].dst == '192.168.1.1' and packet[TCP].dport == 1024:
            print("Decoding packet: ", packet.summary())
            sequence_number = packet[TCP].seq
            print(chr(sequence_number//pre_defined_key))

def start_sniffing():
    print("Starting sniffer...")
    sniff(filter="tcp and dst host 192.168.1.1 and dst port 1024", prn=handle_packet, store=False)

if __name__ == "__main__":
    start_sniffing()

