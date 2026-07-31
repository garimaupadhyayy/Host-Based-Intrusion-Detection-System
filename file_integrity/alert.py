from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class FileAlert:
    alert_type: str        # "FILE_MODIFIED", "FILE_DELETED", "FILE_CREATED"
    severity: str          # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    filepath: str          # full path to the file e.g. C:/Windows/System32/hosts
    description: str       # plain English explanation
    timestamp: datetime = field(default_factory=datetime.now)
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "filepath": self.filepath,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "extra": self.extra
        }