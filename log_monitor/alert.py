from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class LogAlert:
    alert_type: str       # "BRUTE_FORCE", "ERROR_SPIKE", "DANGEROUS_KEYWORD"
    severity: str         # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    log_file: str         # which file triggered it e.g. "C:/Windows/System32/winevt/..."
    description: str      # plain English explanation
    matched_line: str     # the actual log line that caused the alert
    timestamp: datetime = field(default_factory=datetime.now)
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "log_file": self.log_file,
            "description": self.description,
            "matched_line": self.matched_line,
            "timestamp": self.timestamp.isoformat(),
            "extra": self.extra
        }