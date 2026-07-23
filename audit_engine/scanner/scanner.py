import subprocess
from pathlib import Path
from datetime import datetime


SCAN_FOLDER = Path("scans")


def run_scan(target: str) -> str:
    """
    Launch an Nmap scan against the target.
    Returns the path of the generated XML file.
    """

    # Make sure the scans folder exists
    SCAN_FOLDER.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    xml_file = SCAN_FOLDER / f"scan_{timestamp}.xml"

    command = [
        "sudo",
        "nmap",
        "-A",
        "-oX",
        str(xml_file),
        target
    ]

    print(f"[+] Starting scan on {target}...")

    subprocess.run(command, check=True)

    print("[+] Scan completed.")

    return str(xml_file)
