from dataclasses import dataclass, field
from datetime import datetime
from models.scan_result import ScanResult


@dataclass
class LaboratoryReport:

    target: str

    scan_date: datetime

    engine_version: str = "1.0"

    results: list[ScanResult] = field(default_factory=list)

    laboratory_security_score: int = 100

    statistics: dict = field(default_factory=dict)

    recommendations: list[str] = field(default_factory=list)
