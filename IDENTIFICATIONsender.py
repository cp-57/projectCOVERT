
from scapy.all import IP,TCP,send

pre_defined_key = 55

# destination port
dst_ip = "10.10.0.19" 
dst_port = 50000           

# source port
src_ip = "10.10.0.4"
src_port = 50000 


def encode_message(message):
    for letter in message:
        # IP layer
        ip = IP(dst=dst_ip,src=src_ip, id=ord(letter)*pre_defined_key)

        # tcp layer
        tcp = TCP(sport=src_port, dport=dst_port)

        # wrap tcp layer in ip layer
        send(ip/tcp)

encode_message("csaw{licen$e_t0_tr@nsmit_c0vertTCP$$$}")



