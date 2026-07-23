from dataclasses import dataclass


@dataclass
class Finding:
    service: str
    port: int
    severity: str
    description: str
    recommendation: str
    points: int
