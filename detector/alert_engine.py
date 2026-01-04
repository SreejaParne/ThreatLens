import time
from datetime import datetime
import os

ALERT_FILE = "logs/alerts.log"
EVENT_FILE = "logs/events.log"

os.makedirs("logs", exist_ok=True)

failed_attempts = {}

print("[*] Alert Engine started...")

while True:
    ip = "45.33.32.156"
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    count = failed_attempts[ip]

    if count >= 3:
        if count < 6:
            severity = "MEDIUM"
        elif count < 10:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert_msg = f"{timestamp} | {severity} | Brute Force detected | IP={ip}\n"
        event_msg = f"{timestamp} | {severity} | Multiple failed SSH logins | IP={ip}\n"

        with open(ALERT_FILE, "a") as a:
            a.write(alert_msg)

        with open(EVENT_FILE, "a") as e:
            e.write(event_msg)

        print("ALERT:", alert_msg.strip())

        failed_attempts[ip] = 0  # reset after alert

    time.sleep(5)