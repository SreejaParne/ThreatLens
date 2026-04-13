import time
import random
import os

LOG_FILE = "logs/system.log"
os.makedirs("logs", exist_ok=True)

open(LOG_FILE, "w").close()

print("[*] Advanced Log Collector started (60-second rolling window)")

start_time = time.time()

events = [
    "SUCCESS login attempt",
    "FAILED login attempt",
    "ddos traffic spike detected",
    "credential stuffing attempt detected",
    "phishing email reported",
    "ransomware encryption activity detected",
    "privilege escalation attempt detected",
    "lateral movement detected",
    "data exfiltration attempt detected",
    "malicious command execution detected",
    "file upload attack detected"
]

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

while True:

    if time.time() - start_time >= 60:
        open(LOG_FILE, "w").close()
        start_time = time.time()
        print("[*] Log window cleared (60s rotation)")

    timestamp = time.time()
    ip = generate_random_ip()

    event = random.choices(
        events,
        weights=[3, 5, 2, 2, 1, 1, 1, 1, 1, 1, 1],
        k=1
    )[0]

    log_line = f"{timestamp}|{event} ip={ip}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_line)

    print(log_line.strip())
    time.sleep(2)