from scapy.all import sniff, TCP, IP

pre_defined_key = 55

def handle_packet(packet):
    if IP in packet and TCP in packet:
        if packet[IP].dst == '10.10.0.19' and packet[TCP].dport == 50000:
            print("Decoding packet: ", packet.summary())
            identification_number = packet[IP].id
            print(chr(identification_number//pre_defined_key))

def start_sniffing():
    print("Starting sniffer...")
    sniff(filter="tcp and dst host 10.10.0.19 and dst port 50000", prn=handle_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
