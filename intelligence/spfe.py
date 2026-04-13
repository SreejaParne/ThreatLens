import time
from collections import defaultdict
from datetime import datetime

# Track events with time window
event_counter = defaultdict(list)

SUPPRESSION_LIMIT = 5
TIME_WINDOW = 60  # seconds


def pre_filter(log):
    """
    Smart Pre-Filtering Engine (SPFE)
    - Suppresses benign noise
    - Time-window based throttling
    - Adds confidence tagging
    """

    if not log or not log.strip():
        return None

    log = log.strip()
    log_lower = log.lower()
    current_time = time.time()

    # 1️⃣ Suppress known benign patterns
    benign_patterns = [
        "login successful",
        "health check passed",
        "connection established"
    ]

    for pattern in benign_patterns:
        if pattern in log_lower:
            return None

    # 2️⃣ Time-window based suppression
    event_counter[log].append(current_time)

    # Remove old timestamps outside time window
    event_counter[log] = [
        t for t in event_counter[log]
        if current_time - t <= TIME_WINDOW
    ]

    if len(event_counter[log]) > SUPPRESSION_LIMIT:
        return None

    # 3️⃣ Improved confidence tagging
    if any(keyword in log_lower for keyword in ["critical", "unauthorized", "breach"]):
        confidence = "very_high"

    elif any(keyword in log_lower for keyword in ["failed", "error", "attack"]):
        confidence = "high"

    elif "warning" in log_lower:
        confidence = "medium"

    else:
        confidence = "low"

    return {
        "raw_log": log,
        "confidence": confidence,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }