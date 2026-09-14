import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

TEMP_FOLDER = Path("temp")
DISCOVERY_XML = TEMP_FOLDER / "discovery.xml"


def discover_hosts(target):
    """
    Runs nmap -sn (ping sweep) to find active hosts.
    Returns a list of IP address strings for active hosts only.
    Used as the first step in full and port sweep modes.
    """

    TEMP_FOLDER.mkdir(exist_ok=True)

    print(f"[+] Discovering active hosts on {target}...")

    command = [
        "sudo",
        "nmap",
        "-sn",
        "-oX",
        str(DISCOVERY_XML),
        target
    ]

    subprocess.run(command, check=True)

    tree = ET.parse(DISCOVERY_XML)
    root = tree.getroot()

    hosts = []

    for host in root.findall("host"):

        status = host.find("status")

        if status is None:
            continue

        if status.get("state") != "up":
            continue

        address = host.find("address")

        if address is not None:
            hosts.append(address.get("addr"))

    return hosts


def discover_hosts_detailed(target):
    """
    Runs nmap -sn (ping sweep) and returns full host details:
    IP, hostname, MAC address, vendor, and status.
    Used exclusively for the Host Discovery scan mode.
    """

    TEMP_FOLDER.mkdir(exist_ok=True)

    print(f"[+] Running host discovery scan on {target}...")

    command = [
        "sudo",
        "nmap",
        "-sn",
        "-oX",
        str(DISCOVERY_XML),
        target
    ]

    subprocess.run(command, check=True)
    #check : if nmap fails, raise an exception and stop execution

    tree = ET.parse(DISCOVERY_XML)
    root = tree.getroot()

    hosts = []

    for host in root.findall("host"):

        status_el = host.find("status")

        if status_el is None:
            continue

        if status_el.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None

        for address in host.findall("address"):
            addr_type = address.get("addrtype")
            if addr_type == "ipv4":
                ip = address.get("addr")
            elif addr_type == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor")

        if ip is None:
            continue

        hostname = None
        hostname_el = host.find("hostnames/hostname")
        if hostname_el is not None:
            hostname = hostname_el.get("name")

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "status": "up"
        })

    return hosts