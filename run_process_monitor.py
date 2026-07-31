from process_monitor import ProcessMonitor, ProcessAlert

def show_alert(alert: ProcessAlert):
    print("\n" + "="*55)
    print(f"  !! ALERT : {alert.alert_type}")
    print(f"  Severity : {alert.severity}")
    print(f"  Process  : {alert.process_name}  (PID {alert.pid})")
    print(f"  Details  : {alert.description}")
    if alert.extra.get("exe"):
        print(f"  Location : {alert.extra['exe']}")
    print("="*55 + "\n")

print("Starting HIDS Process Monitor...")
print("It will scan all running processes every 5 seconds.")
print("Press Ctrl+C to stop.\n")

monitor = ProcessMonitor(on_alert=show_alert)

try:
    monitor.start()
except KeyboardInterrupt:
    monitor.stop()
    all_alerts = monitor.get_alerts()
    print(f"\nStopped. Total alerts caught: {len(all_alerts)}")
    for a in all_alerts:
        print(f"  - [{a.severity}] {a.alert_type}: {a.process_name} (PID {a.pid})")