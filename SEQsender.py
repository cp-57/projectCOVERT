from scapy.all import IP,TCP,send

pre_defined_key = 505

# destination port
dst_ip = "192.168.1.1" 
dst_port = 1024           

# source port
src_port = 443 
src_ip = "192.168.1.2"


def encode_message(message):
    for letter in message:
        # IP layer
        ip = IP(dst=dst_ip,src=src_ip)

        # tcp layer
        tcp = TCP(sport=src_port, dport=dst_port, seq=ord(letter)*pre_defined_key)

        # wrap tcp layer in ip layer
        send(ip/tcp)

encode_message("Hello World")

def show_options():
    ip = IP()
    tcp = TCP()
    packet = ip/tcp
    packet[TCP].show()   # Show all fields and options of the TCP layer
    print("\nTCP Options:")
    for option in packet[TCP].options:
        print(option)
    

show_options()

