import subprocess
import sys
import time
import webbrowser
import os

# Clear old data on every run
open("data/logs.log", "w").close()
open("data/alerts.log", "w").close()

print("[*] Old logs and alerts cleared")

subprocess.Popen([sys.executable, "detector/log_collector.py"])
time.sleep(1)

subprocess.Popen([sys.executable, "detector/alert_engine.py"])
time.sleep(1)

subprocess.Popen([sys.executable, "dashboard/app.py"])

time.sleep(2)
webbrowser.open("http://127.0.0.1:5000")