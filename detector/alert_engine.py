import time
from datetime import datetime
import os
import csv
import threading

from detector.ip_blocker import auto_block
from intelligence.spfe import pre_filter
from intelligence.threat_intel import enrich_event
from detector.correlation_engine import correlate
from detector.response_engine import suggest_response

# ================= GLOBAL PATHS =================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "system.log")
ALERT_FILE = os.path.join(BASE_DIR, "logs", "alerts.log")
EVENT_FILE = os.path.join(BASE_DIR, "logs", "events.log")
CSV_FILE = os.path.join(BASE_DIR, "logs", "alerts_report.csv")
POSITION_FILE = os.path.join(BASE_DIR, "logs", "engine_position.txt")
BLOCK_FILE = os.path.join(BASE_DIR, "logs", "blocked_ips.txt")

os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

failed_attempts = {}
blocked_ips = set()

# ================= LOAD BLOCKED IPS =================
def load_blocked_ips():
    blocked_ips.clear()
    if os.path.exists(BLOCK_FILE):
        with open(BLOCK_FILE) as f:
            for line in f:
                if "ip=" in line:
                    ip = line.split("ip=")[-1].strip()
                    blocked_ips.add(ip)

# ================= ENSURE CSV HEADER =================
def ensure_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Severity", "Message", "IP"])

# ================= POSITION TRACKING =================
def get_last_position():
    if os.path.exists(POSITION_FILE):
        try:
            with open(POSITION_FILE, "r") as f:
                return int(f.read().strip())
        except:
            return 0
    return 0

def save_last_position(pos):
    with open(POSITION_FILE, "w") as f:
        f.write(str(pos))

# ================= ATTACK DETECTION =================
def detect_attack(line):
    line_lower = line.lower()

    if "failed login" in line_lower:
        return "bruteforce"
    elif "sql" in line_lower:
        return "sql_injection"
    elif "ddos" in line_lower:
        return "ddos"
    elif "credential stuffing" in line_lower:
        return "credential_stuffing"
    elif "phishing" in line_lower:
        return "phishing"
    elif "ransomware" in line_lower:
        return "ransomware"
    elif "privilege escalation" in line_lower:
        return "privilege_escalation"
    elif "lateral movement" in line_lower:
        return "lateral_movement"
    elif "data exfiltration" in line_lower:
        return "data_exfiltration"
    elif "command execution" in line_lower:
        return "command_execution"
    elif "file upload" in line_lower:
        return "file_upload_attack"

    return None

# ================= SEVERITY ASSIGNMENT =================
def assign_severity(attack_type, count):

    if attack_type in ["bruteforce", "credential_stuffing"]:
        if count >= 10: return "CRITICAL"
        if count >= 6: return "HIGH"
        if count >= 3: return "MEDIUM"
        return None

    if attack_type in ["sql_injection", "command_execution", "file_upload_attack", "data_exfiltration"]:
        return "CRITICAL"

    if attack_type in ["ddos", "ransomware", "privilege_escalation", "lateral_movement", "phishing"]:
        return "HIGH"

    return "MEDIUM"

# ================= ENGINE CORE =================
def run_engine():

    load_blocked_ips()
    ensure_csv()

    print("[*] Alert Engine started...")

    while True:
        try:
            if not os.path.exists(LOG_FILE):
                time.sleep(2)
                continue

            with open(LOG_FILE, "r") as f:
                lines = f.readlines()

            last_pos = get_last_position()
            new_lines = lines[last_pos:]

            for raw_line in new_lines:

                filtered = pre_filter(raw_line)
                if not filtered:
                    continue

                line = filtered["raw_log"]

                attack_type = detect_attack(line)
                if not attack_type:
                    continue

                if "ip=" not in line:
                    continue

                ip = line.split("ip=")[-1].strip()

                if ip in blocked_ips:
                    continue

                # Threat Intelligence
                intel = enrich_event(ip)
                threat_score = intel.get("threat_score", 0)

                # Count failed attempts
                if attack_type in ["bruteforce", "credential_stuffing"]:
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                    count = failed_attempts[ip]
                else:
                    count = 1

                severity = assign_severity(attack_type, count)
                if not severity:
                    continue

                # Response decision
                response = suggest_response(ip, severity, threat_score)

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                alert_msg = f"{timestamp}|{severity}|{attack_type}|ThreatScore={threat_score}|Action={response['recommended_action']}|ip={ip}\n"
                event_msg = f"{timestamp}|{severity}|{attack_type}|ThreatScore={threat_score}|ip={ip}\n"

                # Write logs
                with open(ALERT_FILE, "a") as a:
                    a.write(alert_msg)

                with open(EVENT_FILE, "a") as e:
                    e.write(event_msg)

                with open(CSV_FILE, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, severity, attack_type, ip])

                # Correlation
                incident = correlate(ip, severity)
                if incident:
                    with open(EVENT_FILE, "a") as e:
                        e.write(incident + "\n")

                # Clean blocking (ONLY call auto_block)
                if response["recommended_action"] == "BLOCK_IP":
                    blocked_ips.add(ip)
                    auto_block(ip)
                    print(f"🚫 BLOCKED IP: {ip}")

                    if attack_type in ["bruteforce", "credential_stuffing"]:
                        failed_attempts[ip] = 0

            save_last_position(len(lines))
            time.sleep(2)

        except Exception as e:
            print("Engine Error:", e)
            time.sleep(2)

# ================= THREAD STARTER =================
def start_alert_engine():
    thread = threading.Thread(target=run_engine)
    thread.daemon = True
    thread.start()

# ================= ENTRY POINT =================
if __name__ == "__main__":
    run_engine()