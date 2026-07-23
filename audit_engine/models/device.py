from dataclasses import dataclass, field

from models.port import Port


@dataclass
class Device:
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    status: str = "unknown"
    os: str | None = None

    ports: list[Port] = field(default_factory=list)
