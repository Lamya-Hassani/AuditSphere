from pathlib import Path
from datetime import datetime
import subprocess

from config.config_loader import load_config

config = load_config()
SCAN_FOLDER = Path(
    config["engine"]["scan_directory"]
)

def run_scan(target):
    SCAN_FOLDER.mkdir(exist_ok=True)
    filename = SCAN_FOLDER / (
        f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    )
    command = [
        "sudo",
        "nmap",
        *config["scanner"]["detailed_arguments"],
        "-oX",
        str(filename),
        target
    ]

    print(f"[+] Running detailed scan on {target}...")
    subprocess.run(command, check=True)

    return filename