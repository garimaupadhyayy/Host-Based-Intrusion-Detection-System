from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class NetworkAlert:
    alert_type: str
    severity: str
    src_ip: str
    dst_ip: Optional[str]
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "extra": self.extra
        }