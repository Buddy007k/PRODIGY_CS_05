# import socket
# import struct
# import textwrap

# # Create a raw socket
# raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# while True:
#     packet = raw_socket.recvfrom(65535)[0]  # Receive a packet

#     # Unpack IP header
#     ip_header = packet[0:20]
#     iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

#     version_ihl = iph[0]
#     version = version_ihl >> 4
#     ihl = version_ihl & 0xF
#     iph_length = ihl * 4
#     ttl = iph[5]
#     protocol = iph[6]
#     s_addr = socket.inet_ntoa(iph[8])
#     d_addr = socket.inet_ntoa(iph[9])

#     print('IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + \
#       ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source:' + str(s_addr))

import pyshark

# Capture packets on interface 'Ethernet' for 10 packets
capture = pyshark.LiveCapture(interface='Ethernet', display_filter='ip', only_summaries=True)

# Print packet summaries
for packet in capture.sniff_continuously(packet_count=10):
    print(f"Source: {packet.source} -> Destination: {packet.destination}, Protocol: {packet.protocol}")
