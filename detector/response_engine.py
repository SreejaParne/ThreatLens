from detector.ip_blocker import auto_block

# Track repeated offenders
ip_strike_count = {}

def suggest_response(ip, severity, threat_score):
    """
    Intelligent Containment Engine
    Blocks only when risk justifies it
    """

    severity = severity.upper()
    threat_score = max(0, min(threat_score, 100))

    # Track strikes per IP
    if ip not in ip_strike_count:
        ip_strike_count[ip] = 0

    ip_strike_count[ip] += 1

    action = "NO_ACTION"
    business_impact = "NONE"

    # 🚨 CRITICAL → Always Block
    if severity == "CRITICAL":
        action = "BLOCK_IP"
        auto_block(ip)
        business_impact = "LOW"

    # 🔴 HIGH → Block only if high risk OR repeat offender
    elif severity == "HIGH":
        if threat_score >= 80 or ip_strike_count[ip] >= 3:
            action = "BLOCK_IP"
            auto_block(ip)
            business_impact = "LOW"
        else:
            action = "TEMP_MONITOR"

    # 🟡 MEDIUM → Monitor unless repeated many times
    elif severity == "MEDIUM":
        if ip_strike_count[ip] >= 5:
            action = "BLOCK_IP"
            auto_block(ip)
            business_impact = "LOW"
        else:
            action = "TEMP_MONITOR"

    # 🟢 LOW → Just log
    elif severity == "LOW":
        action = "LOG_ONLY"

    safety_score = 100 - threat_score

    return {
        "recommended_action": action,
        "risk_score": threat_score,
        "business_impact": business_impact,
        "safety_score": safety_score,
        "strike_count": ip_strike_count[ip]
    }