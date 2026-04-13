import os
from datetime import datetime

BLOCK_FILE = "logs/blocked_ips.txt"
ALERT_FILE = "logs/alerts.log"

THRESHOLD = 3

os.makedirs("logs", exist_ok=True)


def auto_block(ip):
    """
    Immediate block when called
    Prevents duplicate entries properly
    """

    ip = ip.strip()

    existing_blocked = set()

    if os.path.exists(BLOCK_FILE):
        with open(BLOCK_FILE, "r") as f:
            for line in f:
                if "ip=" in line:
                    extracted_ip = line.split("ip=")[1].strip()
                    existing_blocked.add(extracted_ip)

    if ip in existing_blocked:
        return  # Already blocked

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(BLOCK_FILE, "a") as f:
        block_entry = f"{timestamp}|status=BLOCKED|ip={ip}\n"
        f.write(block_entry)

    print("🚫 AUTO BLOCKED:", ip)

def threshold_blocking():
    """
    Secondary safeguard:
    Scans alerts.log and blocks IPs exceeding threshold
    """

    if not os.path.exists(ALERT_FILE):
        return

    alerts = open(ALERT_FILE).readlines()

    ip_count = {}

    for line in alerts:
        if "IP=" in line:
            ip = line.split("IP=")[1].strip()
            ip_count[ip] = ip_count.get(ip, 0) + 1

    for ip, count in ip_count.items():
        if count >= THRESHOLD:
            auto_block(ip)