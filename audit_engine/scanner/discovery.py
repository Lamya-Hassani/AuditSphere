import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

TEMP_FOLDER = Path("temp")
DISCOVERY_XML = TEMP_FOLDER / "discovery.xml"


def discover_hosts(target):

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