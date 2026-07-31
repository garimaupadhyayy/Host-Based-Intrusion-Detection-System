import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import threading
import time
import json
from datetime import datetime
from collections import deque
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
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

def add_alert(source: str, alert_type: str, severity: str, description: str, extra: dict = {}):
    """Called by each monitor module when it raises an alert."""
    alerts.appendleft({
        "id":          len(alerts),
        "source":      source,
        "alert_type":  alert_type,
        "severity":    severity,
        "description": description,
        "timestamp":   datetime.now().strftime("%H:%M:%S"),
        "extra":       extra
    })
    if source in module_status:
        module_status[source]["alerts"] += 1

def set_module_status(module: str, status: str):
    """Call this when a module starts or stops."""
    if module in module_status:
        module_status[module]["status"] = status

# ── API routes — the dashboard HTML calls these ──────────────────────
@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(alerts))

@app.route("/api/status")
def get_status():
    uptime_seconds = int((datetime.now() - start_time).total_seconds())
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return jsonify({
        "modules": module_status,
        "total_alerts": len(alerts),
        "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

def run_server():
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)