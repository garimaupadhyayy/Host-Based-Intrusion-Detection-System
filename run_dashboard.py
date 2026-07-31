import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
import threading
import platform
import webbrowser

import requests

from app import app, set_module_status

HOST = "127.0.0.1"
PORT = 5000
BASE_URL = f"http://{HOST}:{PORT}"
ALERTS_URL = f"{BASE_URL}/api/alerts"

print("=" * 55)
print("  HIDS Dashboard — Real-Time Windows Host IDS")
print("=" * 55)
print()


# ── 1. Start Flask in its own daemon thread ───────────────────────────
def run_flask():
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


flask_thread = threading.Thread(target=run_flask, daemon=True, name="flask-server")
flask_thread.start()
print(f"[1/2] Flask server starting at {BASE_URL} ...")

# Wait until the server actually answers before wiring up monitors
for _ in range(50):
    try:
        requests.get(f"{BASE_URL}/api/status", timeout=0.5)
        break
    except requests.RequestException:
        time.sleep(0.2)
else:
    print("      WARNING: Flask server did not respond in time — continuing anyway.")

print("      Flask server is up.")

# Open the dashboard in the browser via the Flask route (NOT file://),
# so the page's relative /api/* fetch calls actually reach the server.
webbrowser.open(BASE_URL + "/")
print("[2/2] Dashboard opened in your browser.")
print()


# ── 2. Shared alert relay: every monitor posts to POST /api/alerts ───
def post_alert(source, alert_type, severity, description, extra=None):
    try:
        requests.post(
            ALERTS_URL,
            json={
                "source": source,
                "alert_type": alert_type,
                "severity": severity,
                "description": description,
                "extra": extra or {},
            },
            timeout=2,
        )
    except requests.RequestException as e:
        print(f"  [!] Could not deliver alert to dashboard: {e}")


def make_alert_handler(source):
    def _handler(alert):
        post_alert(
            source=source,
            alert_type=alert.alert_type,
            severity=alert.severity,
            description=alert.description,
            extra=alert.to_dict().get("extra", {}),
        )
    return _handler


def report_status(module, status):
    set_module_status(module, status)
    try:
        requests.post(f"{BASE_URL}/api/status", json={"module": module, "status": status}, timeout=2)
    except requests.RequestException:
        pass


# ── 3. Wire up and launch each real monitor as its own daemon thread ─

def run_network_monitor():
    from network_monitor import NetworkMonitor
    try:
        monitor = NetworkMonitor(on_alert=make_alert_handler("network"))
        report_status("network", "running")
        monitor.start()   # blocks (sniff loop) — runs for life of the thread
    except PermissionError:
        print("  [network] ERROR: Packet sniffing needs Administrator privileges. "
              "Re-run this program as Administrator to enable network monitoring.")
        report_status("network", "error")
    except Exception as e:
        print(f"  [network] ERROR: Could not start network monitor: {e}")
        print("            (On Windows this requires Npcap: https://npcap.com/#download)")
        report_status("network", "error")


def run_process_monitor():
    from process_monitor import ProcessMonitor
    try:
        monitor = ProcessMonitor(on_alert=make_alert_handler("process"))
        report_status("process", "running")
        monitor.start()   # blocks
    except Exception as e:
        print(f"  [process] ERROR: Could not start process monitor: {e}")
        report_status("process", "error")


def run_log_monitor():
    from log_monitor import LogMonitor

    if platform.system() == "Windows":
        log_files = ["C:/Windows/Temp/hids_monitor.log"]
    elif platform.system() == "Darwin":
        log_files = ["/var/log/system.log", "/tmp/hids_monitor.log"]
    else:
        log_files = ["/var/log/syslog", "/var/log/auth.log", "/tmp/hids_monitor.log"]

    # Make sure at least one target file exists so the watcher has
    # something real to tail from the moment it starts.
    fallback = log_files[-1]
    try:
        os.makedirs(os.path.dirname(os.path.abspath(fallback)), exist_ok=True)
        if not os.path.exists(fallback):
            with open(fallback, "w") as f:
                f.write("")
    except OSError:
        pass

    try:
        monitor = LogMonitor(log_files=log_files, on_alert=make_alert_handler("log"))
        report_status("log", "running")
        monitor.start()   # blocks
    except Exception as e:
        print(f"  [log] ERROR: Could not start log monitor: {e}")
        report_status("log", "error")


def run_file_integrity_monitor():
    from file_integrity import FileIntegrityMonitor

    if platform.system() == "Windows":
        watch_paths = [
            "C:/Windows/System32/drivers/etc/hosts",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_watched_files"),
        ]
    else:
        watch_paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_watched_files"),
        ]
    watch_paths = [p for p in watch_paths if os.path.exists(p)]

    try:
        monitor = FileIntegrityMonitor(
            watch_paths=watch_paths,
            baseline_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), "hids_baseline.json"),
            on_alert=make_alert_handler("integrity"),
        )
        report_status("integrity", "running")
        monitor.start()   # blocks
    except Exception as e:
        print(f"  [integrity] ERROR: Could not start file integrity monitor: {e}")
        report_status("integrity", "error")


monitor_threads = [
    threading.Thread(target=run_network_monitor, daemon=True, name="network-monitor"),
    threading.Thread(target=run_process_monitor, daemon=True, name="process-monitor"),
    threading.Thread(target=run_log_monitor, daemon=True, name="log-monitor"),
    threading.Thread(target=run_file_integrity_monitor, daemon=True, name="integrity-monitor"),
]

print("Starting real-time monitors (daemon threads)...")
for t in monitor_threads:
    t.start()
    print(f"  -> {t.name} started")

print()
print("HIDS is live. All monitors and the dashboard are running.")
print(f"Dashboard: {BASE_URL}")
print("Keep this terminal running — press Ctrl+C to stop.\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nShutting down HIDS dashboard...")
