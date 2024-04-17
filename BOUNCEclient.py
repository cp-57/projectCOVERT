from scapy.all import sniff, TCP, IP

pre_defined_key = 505

def handle_packet(packet):
    print("Decoding packet: ", packet.summary())
    if IP in packet and TCP in packet:
        if packet[IP].src == '192.168.1.2' and packet[TCP].sport == 909:
            print("Decoding packet: ", packet.summary())
            sequence_number = packet[TCP].seq
            print(chr(sequence_number//pre_defined_key))

def start_sniffing():
    print("Starting sniffer...")
    sniff(filter="tcp and src host 192.168.1.2 and src port 909", prn=handle_packet, store=False)

if __name__ == "__main__":
    start_sniffing()

