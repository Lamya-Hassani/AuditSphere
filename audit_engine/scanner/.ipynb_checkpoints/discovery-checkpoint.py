import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

from config.config_loader import load_config

config = load_config()
SCAN_FOLDER = Path(
    config["engine"]["scan_directory"]
)


def discover_hosts(network):
    SCAN_FOLDER.mkdir(exist_ok=True)
    filename = SCAN_FOLDER / (
        f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    )
    command = [
        "sudo",
        "nmap",
        *config["scanner"]["discovery_arguments"],
        "-oX",
        str(filename),
        network
    ]

    subprocess.run(command, check=True)
    tree = ET.parse(filename)
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
            hosts.append(
                address.get("addr")
            )

    return hosts