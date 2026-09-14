import subprocess
from pathlib import Path

TEMP_FOLDER = Path("temp")
HOST_XML = TEMP_FOLDER / "host.xml"

NSE_SCRIPTS = ",".join([
    "ftp-anon",           # Is anonymous FTP login allowed?
    "http-title",         # Grab the HTTP page title
    "http-server-header", # What server software?
    "http-methods",       # Which HTTP verbs are allowed (PUT, DELETE...)?
    "ssl-cert",           # SSL certificate details
    "ssl-enum-ciphers",   # Which cipher suites are supported?
    "smb-protocols",      # Is SMBv1 still enabled?
    "smb-security-mode",  # Is SMB signing enforced?
    "ssh2-enum-algos",    # Which SSH algorithms are offered?
    "ssh-hostkey",        # SSH host key fingerprint
    "snmp-info",          # SNMP information
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