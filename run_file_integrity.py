import os
import platform
from file_integrity import FileIntegrityMonitor, FileAlert

def show_alert(alert: FileAlert):
    print("\n" + "="*60)
    print(f"  !! ALERT  : {alert.alert_type}")
    print(f"  Severity  : {alert.severity}")
    print(f"  File      : {alert.filepath}")
    print(f"  Details   : {alert.description}")
    if alert.extra.get("old_hash"):
        print(f"  Old hash  : {alert.extra['old_hash']}")
        print(f"  New hash  : {alert.extra['new_hash']}")
    print("="*60 + "\n")

# ── Create a test folder with some files to watch ───────────────────
TEST_FOLDER = os.path.join(os.getcwd(), "test_watched_files")
os.makedirs(TEST_FOLDER, exist_ok=True)

# Create 3 sample files inside the test folder
for name, content in [
    ("config.txt",   "database_host=localhost\nport=5432\n"),
    ("secrets.txt",  "api_key=ABC123\npassword=hunter2\n"),
    ("readme.txt",   "This is a test file for HIDS.\n"),
]:
    fpath = os.path.join(TEST_FOLDER, name)
    if not os.path.exists(fpath):
        with open(fpath, "w") as f:
            f.write(content)

print("Starting HIDS File Integrity Monitor...")
print(f"Watching folder: {TEST_FOLDER}")
print("Press Ctrl+C to stop.\n")

monitor = FileIntegrityMonitor(
    watch_paths=[TEST_FOLDER],
    baseline_file="hids_baseline.json",
    on_alert=show_alert
)

try:
    monitor.start()
except KeyboardInterrupt:
    monitor.stop()
    all_alerts = monitor.get_alerts()
    print(f"\nStopped. Total alerts: {len(all_alerts)}")
    for a in all_alerts:
        print(f"  - [{a.severity}] {a.alert_type}: {a.filepath}")