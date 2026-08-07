"""
nse_analyzer.py
---------------
Converts Nmap NSE script output (parsed from XML) into structured Findings.

Each rule maps a script ID to a check function.
The check function receives the raw NSE output string
and returns a Finding if a vulnerability is detected, or None.

Only safe, non-intrusive scripts are covered.
"""

from models.finding import Finding


# ---------------------------------------------------------------------------
# NSE rule functions
# Each takes (port, output_string) and returns a Finding or None
# ---------------------------------------------------------------------------

def _check_ftp_anon(port, output: str):
    if "Anonymous FTP login allowed" in output or "anonymous" in output.lower():
        return Finding(
            service="ftp",
            port=port.number,
            product=port.product,
            version=port.version,
            severity="High",
            description="Anonymous FTP login is enabled. Any user can connect without credentials and may be able to read or upload files.",
            recommendation="Disable anonymous FTP login in the FTP server configuration. Migrate to SFTP (SSH File Transfer Protocol) for authenticated, encrypted transfers.",
            points=5,
            source="nse",
        )


def _check_ssl_ciphers(port, output: str):
    findings = []
    output_lower = output.lower()

    if "sslv3" in output_lower or "ssl_3" in output_lower:
        findings.append(Finding(
            service=port.service,
            port=port.number,
            product=port.product,
            version=port.version,
            severity="High",
            description="SSLv3 is enabled. SSLv3 is deprecated and vulnerable to POODLE and other protocol attacks.",
            recommendation="Disable SSLv3 in the server TLS configuration. Enable TLS 1.2 and TLS 1.3 only.",
            points=5,
            source="nse",
        ))

    if "tlsv1.0" in output_lower or "tls_1.0" in output_lower:
        findings.append(Finding(
            service=port.service,
            port=port.number,
            product=port.product,
            version=port.version,
            severity="Medium",
            description="TLSv1.0 is enabled. TLS 1.0 is deprecated and vulnerable to BEAST and other attacks.",
            recommendation="Disable TLS 1.0 and 1.1. Enforce TLS 1.2 as minimum and prefer TLS 1.3.",
            points=3,
            source="nse",
        ))

    if "null" in output_lower or "export" in output_lower or "rc4" in output_lower:
        findings.append(Finding(
            service=port.service,
            port=port.number,
            product=port.product,
            version=port.version,
            severity="High",
            description="Weak or NULL cipher suites are advertised by this TLS service.",
            recommendation="Remove NULL, EXPORT, RC4, and DES cipher suites from the server TLS configuration. Use only AEAD ciphers (AES-GCM, CHACHA20).",
            points=5,
            source="nse",
        ))

    return findings


def _check_smb_protocols(port, output: str):
    output_lower = output.lower()
    if "smbv1" in output_lower or "smb1" in output_lower or "nt lm 0.12" in output_lower:
        return Finding(
            service="microsoft-ds",
            port=port.number,
            product=port.product,
            version=port.version,
            severity="High",
            description="SMBv1 is enabled. SMBv1 is obsolete and was exploited by EternalBlue (CVE-2017-0144) used in WannaCry ransomware.",
            recommendation="Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Ensure SMBv2/v3 is available before disabling.",
            points=5,
            source="nse",
        )


def _check_smb_security(port, output: str):
    output_lower = output.lower()
    if "message signing disabled" in output_lower or "signing: disabled" in output_lower:
        return Finding(
            service="microsoft-ds",
            port=port.number,
            product=port.product,
            version=port.version,
            severity="Medium",
            description="SMB message signing is not enforced. This allows SMB relay attacks (NTLM relay).",
            recommendation="Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true. Also enable on clients via Group Policy.",
            points=3,
            source="nse",
        )


def _check_http_methods(port, output: str):
    dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
    found = [m for m in dangerous if m in output.upper()]
    if found:
        return Finding(
            service=port.service,
            port=port.number,
            product=port.product,
            version=port.version,
            severity="Medium",
            description=f"Potentially dangerous HTTP methods are enabled: {', '.join(found)}. These can be exploited for file upload, cross-site tracing, or proxying attacks.",
            recommendation="Disable unused HTTP methods in the web server configuration. Use an allowlist to permit only GET, POST, HEAD. Block TRACE and OPTIONS at the WAF or firewall.",
            points=3,
            source="nse",
        )


def _check_snmp(port, output: str):
    if output and len(output.strip()) > 10:
        return Finding(
            service="snmp",
            port=port.number,
            product=port.product,
            version=port.version,
            severity="Medium",
            description="SNMP is publicly accessible and returned system information. This may expose OS details, network topology, and hardware inventory.",
            recommendation="Restrict SNMP access with ACLs. Use SNMPv3 with authentication and encryption. Disable SNMP if not required.",
            points=3,
            source="nse",
        )


# ---------------------------------------------------------------------------
# Script dispatch table: script_id → check function
# ---------------------------------------------------------------------------

NSE_CHECKS = {
    "ftp-anon":          _check_ftp_anon,
    "ssl-enum-ciphers":  _check_ssl_ciphers,
    "smb-protocols":     _check_smb_protocols,
    "smb-security-mode": _check_smb_security,
    "http-methods":      _check_http_methods,
    "snmp-info":         _check_snmp,
}


def analyze_nse(device) -> list:
    """
    Iterate over all ports and their NSE outputs.
    Return a flat list of Findings generated from NSE results.
    """
    findings = []

    for port in device.ports:
        for script_id, output in port.nse_output.items():
            checker = NSE_CHECKS.get(script_id)
            if checker is None:
                continue

            result = checker(port, output)

            if result is None:
                continue

            # Some checkers return a list (e.g. ssl-enum-ciphers)
            if isinstance(result, list):
                findings.extend(result)
            else:
                findings.append(result)

    return findings
