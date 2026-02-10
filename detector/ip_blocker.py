import os

BLOCK_FILE = "logs/blocked_ips.txt"
ALERT_FILE = "logs/alerts.log"

THRESHOLD = 3

def auto_block():
    if not os.path.exists(ALERT_FILE):
        return

    alerts = open(ALERT_FILE).readlines()
    ip_count = {}

    for line in alerts:
        if "IP=" in line:
            ip = line.split("IP=")[1].strip()
            ip_count[ip] = ip_count.get(ip, 0) + 1

    os.makedirs("logs", exist_ok=True)

    blocked = set()
    if os.path.exists(BLOCK_FILE):
        blocked = set(open(BLOCK_FILE).read().splitlines())

    with open(BLOCK_FILE, "a") as f:
        for ip, count in ip_count.items():
            if count >= THRESHOLD and ip not in blocked:
                f.write(ip + "\n")
                print("🚫 AUTO BLOCKED:", ip)
