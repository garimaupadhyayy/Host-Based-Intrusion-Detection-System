from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class ProcessAlert:
    alert_type: str        # "HIGH_CPU", "SUSPICIOUS_NAME", "NEW_PROCESS" etc.
    severity: str          # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    pid: int               # Process ID number
    process_name: str      # Name of the process e.g. "python.exe"
    description: str       # Plain English explanation
    timestamp: datetime = field(default_factory=datetime.now)
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "pid": self.pid,
            "process_name": self.process_name,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "extra": self.extra
        }