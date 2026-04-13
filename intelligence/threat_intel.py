import random
from datetime import datetime
import ipaddress


# Simulated Threat Intelligence Database
THREAT_DB = {
    "192.168.1.200": {"reputation": "known_attacker", "base_score": 95},
    "10.0.0.66": {"reputation": "botnet_node", "base_score": 90},
    "172.16.0.99": {"reputation": "malware_host", "base_score": 92},
}


def enrich_event(ip):
    """
    Threat Intelligence Enrichment Layer
    - Validates IP
    - Applies reputation scoring
    - Returns weighted threat score
    """

    # Validate IP format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {
            "threat_score": 0,
            "intel_confidence": "invalid_ip",
            "intel_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # Check threat database
    if ip in THREAT_DB:
        base_score = THREAT_DB[ip]["base_score"]
        reputation = THREAT_DB[ip]["reputation"]

        # Slight dynamic variation
        threat_score = min(100, base_score + random.randint(-3, 3))
        intel_confidence = "high"

    else:
        # Unknown IP scoring model
        threat_score = random.randint(20, 60)
        reputation = "unknown"
        intel_confidence = "medium"

    return {
        "threat_score": threat_score,
        "intel_confidence": intel_confidence,
        "reputation": reputation,
        "intel_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }