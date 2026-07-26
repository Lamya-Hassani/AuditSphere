from dataclasses import dataclass


@dataclass
class Finding:
    service: str
    port: int
    product: str | None = None
    version: str | None = None
    severity: str = ""
    description: str = ""
    recommendation: str = ""
    points: int = 0