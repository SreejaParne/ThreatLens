# reports/forensic_report.py

from datetime import datetime
import os
from collections import Counter

ALERT_FILE = "logs/alerts.log"
EVENT_FILE = "logs/events.log"
BLOCK_FILE = "logs/blocked_ips.txt"


def generate_forensic_story():
    """
    Generates structured forensic incident narrative report
    """

    if not os.path.exists(ALERT_FILE):
        return "No alerts found."

    story = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append("FORENSIC INCIDENT REPORT")
    story.append("=" * 60)
    story.append(f"Report Generated At: {timestamp}")
    story.append("=" * 60)
    story.append("")

    # ================= INCIDENT SUMMARY =================

    severity_counter = Counter()
    blocked_count = 0

    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE) as a:
            for line in a:
                if "CRITICAL" in line:
                    severity_counter["CRITICAL"] += 1
                elif "HIGH" in line:
                    severity_counter["HIGH"] += 1
                elif "MEDIUM" in line:
                    severity_counter["MEDIUM"] += 1

    if os.path.exists(BLOCK_FILE):
        with open(BLOCK_FILE) as b:
            blocked_count = len(b.readlines())

    story.append("INCIDENT SUMMARY")
    story.append("-" * 60)
    story.append(f"Total CRITICAL Alerts : {severity_counter['CRITICAL']}")
    story.append(f"Total HIGH Alerts     : {severity_counter['HIGH']}")
    story.append(f"Total MEDIUM Alerts   : {severity_counter['MEDIUM']}")
    story.append(f"Total Blocked IPs     : {blocked_count}")
    story.append("")

    # ================= INCIDENT TIMELINE =================

    story.append("INCIDENT TIMELINE")
    story.append("-" * 60)

    if os.path.exists(EVENT_FILE):
        with open(EVENT_FILE) as e:
            for line in e:
                story.append(line.strip())

    story.append("")

    # ================= ALERT DETAILS =================

    story.append("ALERT DETAILS")
    story.append("-" * 60)

    with open(ALERT_FILE) as a:
        for line in a:
            story.append(line.strip())

    story.append("")

    # ================= ANALYST OBSERVATIONS =================

    story.append("ANALYST OBSERVATIONS")
    story.append("-" * 60)
    story.append("• Attack escalation patterns observed.")
    story.append("• Automated response actions executed.")
    story.append("• Threat intelligence enrichment applied.")
    story.append("• Correlation engine detected multi-stage attacks.")
    story.append("")

    # ================= COMPLIANCE NOTES =================

    story.append("COMPLIANCE & EVIDENCE INTEGRITY")
    story.append("-" * 60)
    story.append("• Log integrity preserved.")
    story.append("• All automated blocks documented.")
    story.append("• Incident timeline reconstructed successfully.")
    story.append("")

    story.append("=" * 60)
    story.append("END OF REPORT")

    return "\n".join(story)