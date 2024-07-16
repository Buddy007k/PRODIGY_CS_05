from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[Raw].load if Raw in packet else None
        
        print(f"Packet: {src_ip} -> {dst_ip} Protocol: {protocol}")
        if payload:
            print(f"Payload: {payload.hex()}")  # Display payload data in hexadecimal

# Sniff packets
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)
