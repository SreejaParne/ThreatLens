from datetime import datetime

# Track attack progression per IP
attack_tracker = {}

def correlate(ip, severity):
    """
    Adaptive Correlation Intelligence
    Detects escalation pattern per IP
    """

    if ip not in attack_tracker:
        attack_tracker[ip] = {
            "chain": [],
            "incident_triggered": False
        }

    data = attack_tracker[ip]

    # Add severity to chain
    data["chain"].append(severity)

    chain = data["chain"]

    # If incident already triggered, don't repeat
    if data["incident_triggered"]:
        return None

    # Escalation patterns
    escalation_patterns = [
        ["MEDIUM", "HIGH"],
        ["HIGH", "CRITICAL"],
        ["MEDIUM", "HIGH", "CRITICAL"]
    ]

    for pattern in escalation_patterns:
        if all(level in chain for level in pattern):
            data["incident_triggered"] = True
            return generate_incident(ip, chain)

    return None


def generate_incident(ip, chain):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    incident_story = (
        f"{timestamp} | CORRELATED INCIDENT | "
        f"IP={ip} | Attack Progression={chain}\n"
    )

    return incident_story