import xml.etree.ElementTree as ET

from models.device import Device
from models.port import Port


def parse_host(host) -> Device:
    """
    Parse a single <host> element from the Nmap XML
    and return a Device object with ports and NSE output.
    """

    ip = None
    mac = None
    vendor = None
    hostname = None
    status = "unknown"
    operating_system = None

    # Host status
    status_element = host.find("status")
    if status_element is not None:
        status = status_element.get("state", "unknown")

    # Addresses
    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4":
            ip = address.get("addr")
        elif address.get("addrtype") == "mac":
            mac = address.get("addr")
            vendor = address.get("vendor")

    # Hostname
    hostname_element = host.find("hostnames/hostname")
    if hostname_element is not None:
        hostname = hostname_element.get("name")

    # Operating System
    osmatch = host.find("os/osmatch")
    if osmatch is not None:
        operating_system = osmatch.get("name")

    device = Device(
        ip=ip,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        status=status,
        os=operating_system,
    )

    # Open Ports + NSE script output
    ports_element = host.find("ports")
    if ports_element is not None:

        for port_elem in ports_element.findall("port"):

            state_elem = port_elem.find("state")
            if state_elem is None:
                continue
            if state_elem.get("state") != "open":
                continue

            service_elem = port_elem.find("service")

            port_object = Port(
                number=int(port_elem.get("portid")),
                protocol=port_elem.get("protocol"),
                state=state_elem.get("state"),
                service=service_elem.get("name") if service_elem is not None else "unknown",
                product=service_elem.get("product") if service_elem is not None else None,
                version=service_elem.get("version") if service_elem is not None else None,
            )

            # Extract NSE script output for this port
            for script_elem in port_elem.findall("script"):
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")
                if script_id:
                    port_object.nse_output[script_id] = script_output

            device.ports.append(port_object)

    return device


def parse_scan(file_path: str) -> list:
    """
    Parse an Nmap XML file and return a list of Device objects.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()

    devices = []
    for host in root.findall("host"):
        device = parse_host(host)
        devices.append(device)

    return devices
