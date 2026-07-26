import subprocess
from pathlib import Path

TEMP_FOLDER = Path("temp")
HOST_XML = TEMP_FOLDER / "host.xml"


def run_detailed_scan(target):

    TEMP_FOLDER.mkdir(exist_ok=True)

    print(f"[+] Running detailed scan on {target}...")

    command = [
        "sudo",
        "nmap",
        "-A",
        "-oX",
        str(HOST_XML),
        target
    ]

    subprocess.run(command, check=True)

    return HOST_XML