from dataclasses import dataclass, field
from datetime import datetime

from models.device import Device
from models.finding import Finding


@dataclass
class ScanResult:
    device: Device
    scan_date: datetime
    findings: list[Finding] = field(default_factory=list)
    security_score: int = 100
    risk_score: int = 0
    risk_level: str = "Unknown"
