from flask import Flask, render_template, request, redirect, url_for
from detector.attack_analyzer import generate_attack_graph
import os
import matplotlib
matplotlib.use("Agg")

app = Flask(__name__)

# ================= FILE PATHS =================
LOG_FILE = "logs/system.log"
ALERT_FILE = "logs/alerts.log"
EVENT_FILE = "logs/events.log"
ACK_FILE = "logs/acknowledged.log"
RESOLVED_FILE = "logs/resolved.log"

# ================= CLEAR FILES ON START =================
FILES_TO_CLEAR = [
    LOG_FILE,
    ALERT_FILE,
    EVENT_FILE,
    ACK_FILE,
    RESOLVED_FILE
]

for file in FILES_TO_CLEAR:
    os.makedirs(os.path.dirname(file), exist_ok=True)
    open(file, "w").close()

# ================= DASHBOARD =================
@app.route("/")
def dashboard():
    logs = open(LOG_FILE).readlines() if os.path.exists(LOG_FILE) else []
    alerts = open(ALERT_FILE).readlines() if os.path.exists(ALERT_FILE) else []
    acked = open(ACK_FILE).readlines() if os.path.exists(ACK_FILE) else []
    resolved = open("logs/resolved.log").readlines() if os.path.exists("logs/resolved.log") else []

    logs_count = len(logs)
    events_count = len(open(EVENT_FILE).readlines()) if os.path.exists(EVENT_FILE) else 0

    active_alerts = len([a for a in alerts if a not in acked and a not in resolved])
    ack_alerts = len([a for a in alerts if a in acked and a not in resolved])
    resolved_alerts = len(resolved)

    return render_template(
        "index.html",
        log_count=logs_count,
        event_count=events_count,
        active_alerts=active_alerts,
        ack_alerts=ack_alerts,
        resolved_alerts=resolved_alerts
    )

# ================= LOGS =================
@app.route("/logs")
def logs():
    logs = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            for line in f.readlines()[-50:]:
                logs.append({
                    "message": line.strip(),
                    "source": "SSH" if "SSH" in line else "HTTP" if "HTTP" in line else "SYSTEM"
                })

    return render_template("logs.html", logs=logs)

# ================= ALERTS =================
@app.route("/alerts")
def alerts():
    alerts = []
    acknowledged = set()
    resolved = set()

    if os.path.exists(ACK_FILE):
        acknowledged = set(open(ACK_FILE).read().splitlines())

    if os.path.exists(RESOLVED_FILE):
        resolved = set(open(RESOLVED_FILE).read().splitlines())

    if os.path.exists(ALERT_FILE):
        alerts = open(ALERT_FILE).read().splitlines()

    unacked = [a for a in alerts if a not in acknowledged and a not in resolved]
    acked = [a for a in alerts if a in acknowledged and a not in resolved]
    resolved_alerts = [a for a in alerts if a in resolved]

    return render_template(
        "alerts.html",
        unacked_alerts=unacked,
        acked_alerts=acked,
        resolved_alerts=resolved_alerts
    )

# ================= ACK ALERT =================
@app.route("/ack", methods=["POST"])
def acknowledge():
    alert = request.form["alert"]

    with open(ACK_FILE, "a") as f:
        f.write(alert + "\n")

    return redirect(url_for("alerts"))

# ================= EVENTS =================
@app.route("/events")
def events():
    events_list = []

    if os.path.exists(EVENT_FILE):
        with open(EVENT_FILE) as f:
            for line in f.readlines()[-30:]:
                parts = line.strip().split(" | ")
                if len(parts) == 4:
                    events_list.append({
                        "time": parts[0],
                        "severity": parts[1],
                        "message": f"{parts[2]} ({parts[3]})"
                    })

    return render_template("events.html", events=events_list)

# ================= STATS =================
@app.route("/stats")
def stats():
    generate_attack_graph()
    return render_template("stats.html")

# ================= REPORTS =================
@app.route("/reports")
def reports():
    return render_template("reports.html")

@app.route("/resolve", methods=["POST"])
def resolve():
    alert = request.form["alert"]

    with open(RESOLVED_FILE, "a") as f:
        f.write(alert + "\n")

    return redirect(url_for("alerts"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)