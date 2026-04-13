import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")

FILES_TO_RESET = [
    "system.log",
    "alerts.log",
    "events.log",
    "acknowledged.log",
    "resolved.log",
    "blocked_ips.txt",
    "engine_position.txt",
]

os.makedirs(LOG_DIR, exist_ok=True)

for filename in FILES_TO_RESET:
    path = os.path.join(LOG_DIR, filename)
    with open(path, "w") as f:
        f.write("")  # truncate file to zero

print("[*] All logs, alerts, events, acknowledged/resolved alerts, blocked IPs reset to 0.")