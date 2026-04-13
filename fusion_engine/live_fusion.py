import os
from datetime import datetime

LOG_FILE = "logs/system.log"

def fetch_logs_by_time(start_time, end_time):

    results = []

    if not os.path.exists(LOG_FILE):
        return results

    with open(LOG_FILE) as f:
        for line in f:
            try:
                ts, rest = line.strip().split("|", 1)
                ts = float(ts)

                log_time = datetime.fromtimestamp(ts)

                if start_time <= log_time <= end_time:
                    results.append({
                        "time": log_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "message": rest
                    })

            except Exception:
                continue

    return results