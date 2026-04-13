from scapy.all import sniff, IP, TCP
from datetime import datetime

LOG_FILE = "logs/system.log"

def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "OTHER"
        if packet.haslayer(TCP):
            protocol = "TCP"

        timestamp = datetime.now()

        log = f"{timestamp}|{protocol}|traffic|ip={src}\n"

        with open(LOG_FILE, "a") as f:
            f.write(log)

def start_sniffer():
    sniff(prn=process_packet, store=False)