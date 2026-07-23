import xml.etree.ElementTree as ET

from models.device import Device
from models.port import Port


def parse_host(host) -> Device:
    """
    Parse a single <host> element from the Nmap XML
    and return a Device object.
    """

    ip = None
    mac = None
    vendor = None
    hostname = None
    status = "unknown"
    operating_system = None

    # -------------------------
    # Host status
    # -------------------------

    status_element = host.find("status")

    if status_element is not None:
        status = status_element.get("state", "unknown")

    # -------------------------
    # Addresses
    # -------------------------

    for address in host.findall("address"):

        if address.get("addrtype") == "ipv4":
            ip = address.get("addr")

        elif address.get("addrtype") == "mac":
            mac = address.get("addr")
            vendor = address.get("vendor")

    # -------------------------
    # Hostname
    # -------------------------

    hostname_element = host.find("hostnames/hostname")

    if hostname_element is not None:
        hostname = hostname_element.get("name")

    # -------------------------
    # Operating System
    # -------------------------

    osmatch = host.find("os/osmatch")

    if osmatch is not None:
        operating_system = osmatch.get("name")

    # -------------------------
    # Create Device
    # -------------------------

    device = Device(
        ip=ip,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        status=status,
        os=operating_system,
    )

    # -------------------------
    # Open Ports
    # -------------------------

    ports = host.find("ports")

    if ports is not None:

        for port in ports.findall("port"):

            state = port.find("state")

            if state is None:
                continue

            if state.get("state") != "open":
                continue

            service = port.find("service")

            port_object = Port(
                number=int(port.get("portid")),
                protocol=port.get("protocol"),
                state=state.get("state"),
                service=service.get("name") if service is not None else "unknown",
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None,
            )

            device.ports.append(port_object)

    return device


def parse_scan(file_path: str) -> list[Device]:
    """
    Parse an Nmap XML file and return
    a list of Device objects.
    """

    tree = ET.parse(file_path)
    root = tree.getroot()

    devices = []

    for host in root.findall("host"):

        device = parse_host(host)

        devices.append(device)

    return devices
