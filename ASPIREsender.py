from scapy.all import IP, ByteField, StrLenField, Packet, send
import random

# ASPIRE protocol
class ASPIRE(Packet):
    name = "ASPIRE Protocol"
    fields_desc = [
        ByteField("type", 0),
        ByteField("length", 0),
        StrLenField("data", "", length_from=lambda pkt: pkt.length)
    ]

def send_aspire_packet(destination, packet_type, data):
    packet = IP(dst=destination) / ASPIRE(type=packet_type, length=len(data), data=data)
    print(packet.show())
    send(packet)

if __name__ == "__main__":
    dst_ip = "192.168.1.100"
    data_to_send = "Hello, ASPIRE!"
    packet_type = random.randint(0, 255)

    send_aspire_packet(dst_ip, packet_type, data_to_send)
