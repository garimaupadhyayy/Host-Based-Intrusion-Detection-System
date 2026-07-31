from collections import defaultdict
from datetime import datetime, timedelta
from log_monitor.alert import LogAlert

# If we see this many failed login messages within the time window — it's a brute force
FAIL_THRESHOLD = 5
TIME_WINDOW_SEC = 60   # within 1 minute

# Words that appear in failed login log lines
FAIL_KEYWORDS = [
    "failed login", "login failed", "authentication failure",
    "authentication failed", "invalid password", "wrong password",
    "failed password", "bad password", "access denied",
    "logon failure", "failed logon"
]

class BruteForceDetector:
    def __init__(self):
        # {log_file: [timestamps of failures]}
        self._failures: dict[str, list[datetime]] = defaultdict(list)
        self._last_alerted: dict[str, datetime] = {}

    def analyze(self, parsed: dict) -> LogAlert | None:
        message = parsed["message"].lower()
        log_file = parsed["log_file"]
        now = parsed["timestamp"]

        # Check if this line contains any failed login keyword
        is_failure = any(kw in message for kw in FAIL_KEYWORDS)
        if not is_failure:
            return None

        # Record this failure
        self._failures[log_file].append(now)

        # Clean up old ones outside the time window
        cutoff = now - timedelta(seconds=TIME_WINDOW_SEC)
        self._failures[log_file] = [
            t for t in self._failures[log_file] if t > cutoff
        ]

        count = len(self._failures[log_file])

        # Check if we already alerted recently (avoid spam)
        last = self._last_alerted.get(log_file)
        if last and (now - last).seconds < TIME_WINDOW_SEC:
            return None

        if count >= FAIL_THRESHOLD:
            self._last_alerted[log_file] = now
            return LogAlert(
                alert_type="BRUTE_FORCE",
                severity="HIGH",
                log_file=log_file,
                description=f"Brute force detected! {count} failed login attempts in {TIME_WINDOW_SEC} seconds",
                matched_line=parsed["raw"],
                extra={"failure_count": count, "window_seconds": TIME_WINDOW_SEC}
            )

        return None