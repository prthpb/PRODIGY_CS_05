import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.utils import wrpcap
import keyboard

captured_packets = []

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, str(proto))

        payload = b""
        if Raw in packet:
            payload = packet[Raw].load

        print("Time:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Protocol:", proto_name)
        print("Payload:", payload.decode(errors='ignore'))
        print("-" * 50)

        captured_packets.append(packet)

def start_sniffer():
    print("Starting Packet Sniffer...")
    print("Press ESC to stop capturing packets.")
    sniff(prn=process_packet, stop_filter=lambda x: keyboard.is_pressed('esc'))
    wrpcap("captured_packets.pcap", captured_packets)

start_sniffer()
