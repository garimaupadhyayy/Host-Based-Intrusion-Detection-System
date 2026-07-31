import os
import psutil
from process_monitor.alert import ProcessAlert

# Thresholds — you can change these numbers
CPU_THRESHOLD = 85.0       # alert if a single process uses more than 85% CPU (system-wide %)
MEMORY_THRESHOLD = 75.0    # alert if a single process uses more than 75% RAM

# These are kernel/OS bookkeeping "processes", not real programs — psutil
# reports huge, meaningless CPU numbers for them. Never treat them as abuse.
SYSTEM_NOISE_NAMES = {
    "system idle process",  # Windows
    "system",                # Windows kernel
    "idle",                  # some platforms
    "kernel_task",           # macOS
}

_CPU_COUNT = psutil.cpu_count(logical=True) or 1

class ResourceAbuseDetector:
    def __init__(self):
        self._alerted_pids = set()  # remember who we already alerted about

    def analyze(self, process: dict) -> ProcessAlert | None:
        pid = process["pid"]
        name = process["name"]
        mem = process["memory_percent"]

        if name.lower() in SYSTEM_NOISE_NAMES:
            return None

        # psutil's per-process cpu_percent can exceed 100% on multi-core
        # machines (100% per core). Normalize to a system-wide percentage
        # so a 4-core box doesn't falsely flag a process idling at ~110%.
        raw_cpu = process["cpu_percent"]
        cpu = raw_cpu / _CPU_COUNT

        # Check CPU abuse
        if cpu > CPU_THRESHOLD:
            if pid not in self._alerted_pids:
                self._alerted_pids.add(pid)
                return ProcessAlert(
                    alert_type="HIGH_CPU",
                    severity="HIGH",
                    pid=pid,
                    process_name=name,
                    description=f"'{name}' (PID {pid}) is using {cpu:.1f}% CPU — possible crypto miner or malware",
                    extra={"cpu_percent": cpu, "memory_percent": mem}
                )

        # Check memory abuse
        if mem > MEMORY_THRESHOLD:
            if pid not in self._alerted_pids:
                self._alerted_pids.add(pid)
                return ProcessAlert(
                    alert_type="HIGH_MEMORY",
                    severity="MEDIUM",
                    pid=pid,
                    process_name=name,
                    description=f"'{name}' (PID {pid}) is using {mem:.1f}% of RAM — possible memory leak or malware",
                    extra={"cpu_percent": cpu, "memory_percent": mem}
                )

        # If it came back down, remove from alerted list so we can alert again later
        if pid in self._alerted_pids and cpu < CPU_THRESHOLD and mem < MEMORY_THRESHOLD:
            self._alerted_pids.discard(pid)

        return None