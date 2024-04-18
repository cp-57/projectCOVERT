import os
import pyshark


# Path to the PCAP file
pcap_file_path = 'chall.pcapng'

# Use TLS keys to decrypt web traffic
capture = pyshark.FileCapture(
    pcap_file_path, use_json=True, include_raw=True,
    override_prefs={'ssl.keylog_file': os.path.abspath('keys.log')})

# Initialize a list to store the IP IDs
ip_ids = []

packet_count=0

# Iterate over each packet in the capture
for packet in capture:
    packet_count += 1
    """ Get HTTP packet with hint (used by competitors for identifying 
    the covert method used to encode data - IP identification field - along with the key)"""
    if packet_count == 21:
        hex_data = packet.http.file_data.replace(':', '')
        byte_data = bytes.fromhex(hex_data)
        text_data = byte_data.decode('utf-8')
        print("HTTP Text Data:", text_data)

    # This is the source IP of the person sending the covert IP messages
    if 'IP' in packet and packet.ip.src == '10.10.0.4':
        # Append the IP ID to the list
        ip_ids.append(int(packet.ip.id, 16))


capture.close()

key = 55
flag = ""
# Decode and append each ascii character
for id in ip_ids:
    flag+=chr(id//55)

print("Flag:", flag)


