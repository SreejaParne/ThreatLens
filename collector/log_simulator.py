import time
import random
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "system.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ---------------- ATTACK TYPES ----------------
ATTACKS = [
    {"name": "BRUTE_FORCE", "pattern": "login failed", "weight": 5},
    {"name": "CREDENTIAL_STUFFING", "pattern": "multiple login attempts", "weight": 3},
    {"name": "DDOS", "pattern": "too many requests", "weight": 2},
    {"name": "SQL_INJECTION", "pattern": "union select", "weight": 2},
    {"name": "XSS", "pattern": "<script>", "weight": 2},
    {"name": "COMMAND_EXECUTION", "pattern": "/bin/bash", "weight": 1},
    {"name": "FILE_UPLOAD_ATTACK", "pattern": "file upload .php", "weight": 1},
    {"name": "RANSOMWARE", "pattern": "files encrypted", "weight": 1},
    {"name": "PHISHING", "pattern": "fake login page", "weight": 2},
    {"name": "PRIVILEGE_ESCALATION", "pattern": "root access gained", "weight": 1},
    {"name": "LATERAL_MOVEMENT", "pattern": "remote login from internal", "weight": 1},
    {"name": "DATA_EXFILTRATION", "pattern": "large data transfer", "weight": 1},
    {"name": "PORT_SCAN", "pattern": "connection attempt port=", "weight": 3}
]

# ---------------- SIMULATOR ----------------

def generate_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def simulate_attack():
    attack = random.choices(ATTACKS, weights=[a["weight"] for a in ATTACKS])[0]
    ip = generate_ip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if attack["name"] == "PORT_SCAN":
        port = random.randint(20, 1024)
        line = f"{timestamp} | {attack['pattern']}{port} | ip={ip}\n"
    else:
        line = f"{timestamp} | {attack['pattern']} | ip={ip}\n"
    return line

def run_simulator(interval=1):
    print("[*] Log Simulator started...")
    while True:
        line = simulate_attack()
        with open(LOG_FILE, "a") as f:
            f.write(line)
        time.sleep(interval)  # seconds

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    run_simulator()