import time
from network_monitor import NetworkMonitor

def show_alert(alert):
    print("\n" + "="*50)
    print(f"  !! ALERT: {alert.alert_type}")
    print(f"  Severity : {alert.severity}")
    print(f"  From IP  : {alert.src_ip}")
    print(f"  Details  : {alert.description}")
    print("="*50 + "\n")

print("Starting HIDS Network Monitor...")
print("Press Ctrl+C anytime to stop.\n")

monitor = NetworkMonitor(on_alert=show_alert)

try:
    monitor.start()
except KeyboardInterrupt:
    monitor.stop()
    print("\nStopped. Here are all alerts caught:")
    for a in monitor.get_alerts():
        print(f"  - {a.alert_type}: {a.description}")