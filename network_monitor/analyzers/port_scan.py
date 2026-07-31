from collections import defaultdict
from datetime import datetime, timedelta
from network_monitor.alert import NetworkAlert

SYN_THRESHOLD = 20
TIME_WINDOW_SEC = 10

class PortScanDetector:
    def __init__(self):
        self._syn_tracker = defaultdict(dict)

    def analyze(self, parsed):
        tcp = parsed.get("tcp")
        if not tcp:
            return None

        flags = tcp["flags_str"]
        if "S" not in flags or "A" in flags:
            return None

        src = parsed["src_ip"]
        dst_port = tcp["dst_port"]
        now = parsed["timestamp"]

        cutoff = now - timedelta(seconds=TIME_WINDOW_SEC)
        self._syn_tracker[src] = {
            p: t for p, t in self._syn_tracker[src].items() if t > cutoff
        }
        self._syn_tracker[src][dst_port] = now

        unique_ports = len(self._syn_tracker[src])
        if unique_ports >= SYN_THRESHOLD:
            return NetworkAlert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                src_ip=src,
                dst_ip=parsed["dst_ip"],
                description=f"Port scan! {unique_ports} ports probed from {src} in {TIME_WINDOW_SEC}s",
                extra={"ports_probed": list(self._syn_tracker[src].keys())}
            )
        return None