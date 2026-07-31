import os
import platform
from log_monitor import LogMonitor, LogAlert

def show_alert(alert: LogAlert):
    print("\n" + "="*60)
    print(f"  !! ALERT  : {alert.alert_type}")
    print(f"  Severity  : {alert.severity}")
    print(f"  Log File  : {alert.log_file}")
    print(f"  Details   : {alert.description}")
    print(f"  Log Line  : {alert.matched_line[:80]}...")
    print("="*60 + "\n")

# ── Pick the right log files for your operating system ──────────────
if platform.system() == "Windows":
    LOG_FILES = [
        "C:/Windows/Temp/test_hids.log",   # we will create this test file below
    ]
elif platform.system() == "Darwin":  # Mac
    LOG_FILES = [
        "/var/log/system.log",
        "/tmp/test_hids.log",
    ]
else:  # Linux
    LOG_FILES = [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/tmp/test_hids.log",
    ]

# ── Create a test log file so you can see it work immediately ────────
test_log = LOG_FILES[0]
os.makedirs(os.path.dirname(os.path.abspath(test_log)), exist_ok=True)
if not os.path.exists(test_log):
    with open(test_log, "w") as f:
        f.write("2026-05-11 12:00:00 INFO Log monitor test file started\n")
    print(f"Created test log file at: {test_log}")

print("Starting HIDS Log Monitor...")
print("Watching these files for threats:")
for f in LOG_FILES:
    print(f"   -> {f}")
print("\nPress Ctrl+C to stop.\n")

monitor = LogMonitor(log_files=LOG_FILES, on_alert=show_alert)

try:
    monitor.start()
except KeyboardInterrupt:
    monitor.stop()
    all_alerts = monitor.get_alerts()
    print(f"\nStopped. Total alerts: {len(all_alerts)}")
    for a in all_alerts:
        print(f"  - [{a.severity}] {a.alert_type}: {a.description}")