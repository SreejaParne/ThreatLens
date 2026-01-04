import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import time
import os
from collections import defaultdict

LOG_FILE = "logs/system.log"
ALERT_FILE = "logs/alerts.log"
STATIC_DIR = "dashboard/static"

BAR_IMG = os.path.join(STATIC_DIR, "attack_graph.png")
PIE_IMG = os.path.join(STATIC_DIR, "attack_pie.png")

# Track failures per IP (time window)
failed_attempts = defaultdict(list)

def get_severity(ip):
    now = time.time()

    # Keep only last 60 seconds
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t <= 60]
    count = len(failed_attempts[ip])

    if count >= 10:
        return "CRITICAL"
    elif count >= 6:
        return "HIGH"
    elif count >= 3:
        return "MEDIUM"
    else:
        return "LOW"

def generate_attack_graph():
    now = time.time()
    window = 15  # seconds

    failed = 0
    success = 0

    if not os.path.exists(LOG_FILE):
        return

    with open(LOG_FILE) as f:
        for line in f:
            try:
                ts, rest = line.strip().split("|", 1)
                ts = float(ts)

                if now - ts <= window:
                    if "FAILED" in rest:
                        failed += 1

                        ip = rest.split("ip=")[-1]
                        failed_attempts[ip].append(ts)

                        severity = get_severity(ip)

                        alert = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {severity} | Brute Force detected | IP={ip}\n"
                        with open(ALERT_FILE, "a") as af:
                            af.write(alert)

                    elif "SUCCESS" in rest:
                        success += 1
            except:
                continue

    # BAR GRAPH
    plt.figure()
    plt.bar(["FAILED", "SUCCESS"], [failed, success])
    plt.title("Login Attempts (Last 15 Seconds)")
    plt.ylabel("Count")
    plt.savefig(BAR_IMG)
    plt.close()

    # PIE GRAPH
    plt.figure()
    plt.pie(
        [failed, success],
        labels=["FAILED", "SUCCESS"],
        autopct="%1.1f%%",
        startangle=90
    )
    plt.title("Attack Distribution (15s Window)")
    plt.savefig(PIE_IMG)
    plt.close()