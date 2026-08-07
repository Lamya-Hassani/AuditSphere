from dataclasses import dataclass, field


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    product: str | None = None
    version: str | None = None
    # NSE script output: { script_id: output_string }
    nse_output: dict = field(default_factory=dict)
