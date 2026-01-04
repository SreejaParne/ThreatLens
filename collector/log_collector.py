import time
import random
import os

LOG_FILE = "logs/system.log"
os.makedirs("logs", exist_ok=True)

# 🔥 Clear logs at program start
open(LOG_FILE, "w").close()

ips = ["45.33.32.156", "10.0.0.5", "192.168.1.10"]
statuses = ["SUCCESS", "FAILED", "FAILED"]  # more failures = realistic

print("[*] Log Collector started (60-second rolling window)")

start_time = time.time()

while True:
    # ⏱ Rotate logs every 60 seconds
    if time.time() - start_time >= 60:
        open(LOG_FILE, "w").close()
        start_time = time.time()
        print("[*] Log window cleared (60s rotation)")

    ip = random.choice(ips)
    status = random.choice(statuses)
    timestamp = time.time()

    log = f"{timestamp}|{status} login attempt ip={ip}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log)

    print(log.strip())
    time.sleep(2)