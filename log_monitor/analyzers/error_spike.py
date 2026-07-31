from collections import defaultdict
from datetime import datetime, timedelta
from log_monitor.alert import LogAlert

ERROR_THRESHOLD = 10    # more than 10 errors in the window = spike
TIME_WINDOW_SEC = 30

ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL", "SEVERE"}

class ErrorSpikeDetector:
    def __init__(self):
        self._errors: dict[str, list[datetime]] = defaultdict(list)
        self._last_alerted: dict[str, datetime] = {}

    def analyze(self, parsed: dict) -> LogAlert | None:
        level = parsed["level"].upper()
        log_file = parsed["log_file"]
        now = parsed["timestamp"]

        if level not in ERROR_LEVELS:
            return None

        # Record this error
        self._errors[log_file].append(now)

        # Clean up old ones
        cutoff = now - timedelta(seconds=TIME_WINDOW_SEC)
        self._errors[log_file] = [
            t for t in self._errors[log_file] if t > cutoff
        ]

        count = len(self._errors[log_file])

        # Avoid alert spam
        last = self._last_alerted.get(log_file)
        if last and (now - last).seconds < TIME_WINDOW_SEC:
            return None

        if count >= ERROR_THRESHOLD:
            self._last_alerted[log_file] = now
            return LogAlert(
                alert_type="ERROR_SPIKE",
                severity="MEDIUM",
                log_file=log_file,
                description=f"Error spike: {count} {level} messages in {TIME_WINDOW_SEC}s — system may be under attack or crashing",
                matched_line=parsed["raw"],
                extra={"error_count": count, "level": level}
            )

        return None