from dataclasses import dataclass, field


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
    # CVE enrichment fields
    cve_id: str | None = None
    cvss: float | None = None
    cve_data: list = field(default_factory=list)
    # NSE flag
    source: str = "rule"   # "rule" | "version" | "cve" | "nse"