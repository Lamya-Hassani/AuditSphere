import subprocess
from pathlib import Path

TEMP_FOLDER = Path("temp")
HOST_XML = TEMP_FOLDER / "host.xml"

# Safe, non-intrusive NSE discovery scripts
NSE_SCRIPTS = ",".join([
    "ftp-anon",
    "http-title",
    "http-server-header",
    "http-methods",
    "ssl-cert",
    "ssl-enum-ciphers",
    "smb-protocols",
    "smb-security-mode",
    "ssh2-enum-algos",
    "ssh-hostkey",
    "snmp-info",
])


def run_detailed_scan(target):

    TEMP_FOLDER.mkdir(exist_ok=True)

    print(f"[+] Running detailed scan on {target}...")

    command = [
        "sudo",
        "nmap",
        "-A",
        "--script", NSE_SCRIPTS,
        "-oX", str(HOST_XML),
        target
    ]

    subprocess.run(command, check=True)

    return HOST_XML