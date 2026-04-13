import os
from collections import Counter
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ALERT_FILE = os.path.join(BASE_DIR, "logs", "alerts.log")
BLOCK_FILE = os.path.join(BASE_DIR, "logs", "blocked_ips.txt")


def get_statistics():

    stats = {
        "total_alerts": 0,
        "severity_count": {},
        "attack_type_count": {},
        "blocked_ips": 0,
        "top_attacker": None,
        "detection_rate": 0,
        "soc_efficiency": 0,
        "risk_index": 0
    }

    if not os.path.exists(ALERT_FILE):
        return stats

    severity_counter = Counter()
    attack_counter = Counter()
    ip_counter = Counter()

    critical_high = 0
    total_risk_score = 0

    with open(ALERT_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) < 6:
                continue

            severity = parts[1]
            attack_type = parts[2]

            severity_counter[severity] += 1
            attack_counter[attack_type] += 1
            stats["total_alerts"] += 1

            if severity in ["CRITICAL", "HIGH"]:
                critical_high += 1

            for p in parts:
                if p.startswith("ThreatScore="):
                    total_risk_score += int(p.split("=")[1])
                if p.startswith("ip="):
                    ip_counter[p.split("=")[1]] += 1

    stats["severity_count"] = dict(severity_counter)
    stats["attack_type_count"] = dict(attack_counter)

    if ip_counter:
        stats["top_attacker"] = ip_counter.most_common(1)[0]

    # Blocked IP count
    if os.path.exists(BLOCK_FILE):
        with open(BLOCK_FILE) as f:
            stats["blocked_ips"] = sum(1 for _ in f)

    # 1️⃣ Detection Rate %
    if stats["total_alerts"] > 0:
        stats["detection_rate"] = round(
            (critical_high / stats["total_alerts"]) * 100, 2
        )

    # 2️⃣ SOC Efficiency %
    if stats["total_alerts"] > 0:
        stats["soc_efficiency"] = round(
            (stats["blocked_ips"] / stats["total_alerts"]) * 100, 2
        )

    # 3️⃣ Risk Index Score (0-100)
    if stats["total_alerts"] > 0:
        avg_risk = total_risk_score / stats["total_alerts"]
        stats["risk_index"] = round(avg_risk, 2)

    return stats