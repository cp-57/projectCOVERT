from scapy.all import IP,TCP,send

pre_defined_key = 505

# destination port
dst_ip = "127.0.0.1" 
dst_port = 8080           

# source port
src_port = 80 
src_ip = "192.168.1.2"


def encode_message(message):
    for letter in message:
        # IP layer
        ip = IP(dst=dst_ip,src=src_ip, id=ord(letter)*pre_defined_key)

        # tcp layer
        tcp = TCP(sport=src_port, dport=dst_port)

        # wrap tcp layer in ip layer
        send(ip/tcp)

encode_message("Hello World")



