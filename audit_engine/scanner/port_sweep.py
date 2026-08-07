import subprocess
from pathlib import Path

TEMP_FOLDER = Path("temp")


def run_port_sweep(target):
    """
    Runs a fast port sweep using nmap -sV --open -T4.
    Enumerates open ports and grabs service/version banners.
    Does NOT run OS detection or NSE scripts.
    Returns the path to the saved XML file.
    """

    TEMP_FOLDER.mkdir(exist_ok=True)

    xml_file = TEMP_FOLDER / f"portsweep_{target.replace('/', '_').replace('.', '_')}.xml"

    print(f"[+] Running port sweep on {target}...")

    command = [
        "sudo",
        "nmap",
        "-sV",        # Service/version detection
        "--open",     # Only show open ports
        "-T4",        # Aggressive timing (fast)
        "-oX",
        str(xml_file),
        target
    ]

    subprocess.run(command, check=True)

    return xml_file
