from dataclasses import dataclass


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    product: str | None = None
    version: str | None = None

#@dataclass automatically creates:
   #constructor (__init__)
   #readable printing (__repr__)
   #comparisons (__eq__)
