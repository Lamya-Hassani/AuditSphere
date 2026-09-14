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

    # default_factory is  used to create a new list for each instance of the Device class, 
    # ensuring that each device has its own separate list of ports.
    ports: list[Port] = field(default_factory=list)
