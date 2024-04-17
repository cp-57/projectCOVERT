from scapy.all import *

# Define the custom ASPIRE packet
class ASPIRE(Packet):
    name = "ASPIRE Protocol"
    fields_desc = [
        ByteField("type", 0),
        ByteField("length", 0),
        StrLenField("data", "", length_from=lambda pkt: pkt.length)
    ]

def packet_callback(packet):
    if ASPIRE in packet:
        print("Received ASPIRE Packet: ", packet[ASPIRE].data)

# Start sniffing
if __name__ == "__main__":
    sniff(filter="ip", prn=packet_callback)
