import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import os

# ================= FILE PATHS =================
LOG_FILE = "logs/system.log"
ALERT_FILE = "logs/alerts.log"
EVENT_FILE = "logs/events.log"
BLOCK_FILE = "logs/blocked_ips.txt"

STATIC_DIR = "static"

BAR_IMG = os.path.join(STATIC_DIR, "attack_graph.png")
PIE_IMG = os.path.join(STATIC_DIR, "attack_pie.png")

os.makedirs(STATIC_DIR, exist_ok=True)


# ================= COUNT FUNCTIONS =================
def count_lines(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return sum(1 for _ in f)
    return 0


def count_login_status():
    failed = 0
    success = 0

    if not os.path.exists(LOG_FILE):
        return failed, success

    with open(LOG_FILE, "r") as f:
        for line in f:
            if "FAILED" in line:
                failed += 1
            elif "SUCCESS" in line:
                success += 1

    return failed, success


# ================= GENERATE GRAPHS =================
def generate_attack_graph():

    alerts_count = count_lines(ALERT_FILE)
    events_count = count_lines(EVENT_FILE)
    blocked_count = count_lines(BLOCK_FILE)
    failed_count, success_count = count_login_status()

    labels = [
        "Alerts",
        "Events",
        "Blocked IPs",
        "FAILED",
        "SUCCESS"
    ]

    values = [
        alerts_count,
        events_count,
        blocked_count,
        failed_count,
        success_count
    ]

    # ---------- BAR GRAPH ----------
    plt.figure()
    plt.bar(labels, values)
    plt.title("Security System Statistics")
    plt.ylabel("Count")
    plt.xticks(rotation=30)
    plt.savefig(BAR_IMG)
    plt.close()

    # ---------- PIE GRAPH ----------
    plt.figure()

    if sum(values) == 0:
        values = [1] * len(values)

    plt.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        startangle=90
    )
    plt.title("System Log Distribution")
    plt.savefig(PIE_IMG)
    plt.close()