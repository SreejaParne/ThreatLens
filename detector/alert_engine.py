import time
from datetime import datetime
import os
from detector.ip_blocker import auto_block

# 🔄 Auto reset logs on every run
files = [
    "logs/alerts.log",
    "logs/events.log",
    "logs/blocked_ips.txt"
]

for f in files:
    open(f, "w").close()


LOG_FILE = "logs/system.log"
ALERT_FILE = "logs/alerts.log"
EVENT_FILE = "logs/events.log"
BLOCK_FILE = "logs/blocked_ips.log"

os.makedirs("logs", exist_ok=True)

failed_attempts = {}
open(BLOCK_FILE, "w").close()
blocked_ips = set()
last_processed_line = 0   # prevents duplicate processing

# Load blocked IPs
if os.path.exists(BLOCK_FILE):
    with open(BLOCK_FILE) as f:
        blocked_ips = set(f.read().splitlines())

print("[*] Alert Engine started...")

def extract_ip(line):
    if "ip=" in line:
        return line.split("ip=")[1].strip()
    return None

processed = set()
while True:

    if not os.path.exists(LOG_FILE):
        time.sleep(2)
        continue

    with open(LOG_FILE) as f:
        lines = f.readlines()

    # process only NEW lines
    new_lines = lines[last_processed_line:]
    last_processed_line = len(lines)

    for line in new_lines:
        if line in processed:
            continue
        processed.add(line)


        if "FAILED" not in line:
            continue

        ip = extract_ip(line)
        if not ip:
            continue

        if ip in blocked_ips:
            continue

        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        count = failed_attempts[ip]

        if count >= 10:
            severity = "CRITICAL"
        elif count >= 6:
            severity = "HIGH"
        elif count >= 3:
            severity = "MEDIUM"
        else:
            continue

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert_msg = f"{timestamp} | {severity} | Brute Force detected | IP={ip}\n"
        event_msg = f"{timestamp} | {severity} | Multiple failed SSH logins | IP={ip}\n"

        # write alert
        with open(ALERT_FILE, "a") as a:
            a.write(alert_msg)

        # write event
        with open(EVENT_FILE, "a") as e:
            e.write(event_msg)

        print("🚨 ALERT:", alert_msg.strip())

        # AUTO BLOCK
        if severity == "CRITICAL":
            blocked_ips.add(ip)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open("logs/blocked_ips.txt", "a") as f:
                f.write(f"{timestamp}|status=BLOCKED|ip={ip}\n")

            print("🔥 AUTO BLOCKED:", ip)


            failed_attempts[ip] = 0
            auto_block()

    time.sleep(3)