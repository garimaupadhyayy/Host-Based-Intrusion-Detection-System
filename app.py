import os
from datetime import datetime
from collections import deque

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

app = Flask(__name__, static_folder=None)
CORS(app)

# ── Shared alert storage ─────────────────────────────────────────────
alerts = deque(maxlen=200)   # stores last 200 alerts from ALL modules
module_status = {
    "network":   {"status": "stopped", "alerts": 0},
    "process":   {"status": "stopped", "alerts": 0},
    "log":       {"status": "stopped", "alerts": 0},
    "integrity": {"status": "stopped", "alerts": 0},
}
start_time = datetime.now()


def add_alert(source, alert_type, severity, description, extra=None):
    """Append a new alert to the shared feed. Called either directly
    (in-process) or via the POST /api/alerts endpoint below."""
    alerts.appendleft({
        "id": len(alerts), "source": source, "alert_type": alert_type,
        "severity": severity, "description": description,
        "timestamp": datetime.now().strftime("%H:%M:%S"), "extra": extra or {}
    })
    if source in module_status:
        module_status[source]["alerts"] += 1


def set_module_status(module, status):
    """Call this when a monitor module starts, stops, or errors out."""
    if module in module_status:
        module_status[module]["status"] = status


# ── API routes — the dashboard HTML and the monitor modules use these ─
@app.route("/api/alerts", methods=["GET", "POST"])
def alerts_endpoint():
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        source = data.get("source", "unknown")
        alert_type = data.get("alert_type", "UNKNOWN")
        severity = data.get("severity", "LOW")
        description = data.get("description", "")
        extra = data.get("extra", {})

        if not description:
            return jsonify({"error": "description is required"}), 400

        add_alert(source, alert_type, severity, description, extra)
        return jsonify({"status": "ok"}), 201

    return jsonify(list(alerts))


@app.route("/api/status", methods=["GET"])
def get_status():
    uptime_seconds = int((datetime.now() - start_time).total_seconds())
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return jsonify({
        "modules": module_status, "total_alerts": len(alerts),
        "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/api/status", methods=["POST"])
def post_status():
    """Allow monitor modules to report their running/stopped/error state."""
    data = request.get_json(force=True, silent=True) or {}
    module = data.get("module")
    status = data.get("status")
    if not module or not status:
        return jsonify({"error": "module and status are required"}), 400
    set_module_status(module, status)
    return jsonify({"status": "ok"}), 200


@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "dashboard.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
