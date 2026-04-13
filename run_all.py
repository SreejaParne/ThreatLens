import subprocess
import sys
import time
import webbrowser
import os


# ================= CLEAR OLD LOGS =================

LOG_FILES = [
    "logs/system.log",
    "logs/alerts.log",
    "logs/events.log",
    "logs/alerts_report.csv",
    "logs/blocked_ips.txt"
]

os.makedirs("logs", exist_ok=True)

for file in LOG_FILES:
    open(file, "w").close()

print("[*] Old logs cleared")


# ================= START SERVICES =================

print("[*] Starting Log Collector...")
subprocess.Popen([sys.executable, "detector/log_collector.py"])

time.sleep(1)

print("[*] Starting Dashboard...")
subprocess.Popen([sys.executable, "app.py"])   # If your Flask app is app.py in root

time.sleep(2)

webbrowser.open("http://127.0.0.1:5000")

print("[*] ThreatLens System Running...")