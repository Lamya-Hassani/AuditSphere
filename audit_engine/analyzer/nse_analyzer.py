from models.finding import Finding


def check_ftp_anonymous(port, output):
    if "anonymous" not in output.lower():
        return None

    return Finding(
        service="ftp",
        port=port.number,
        product=port.product,
        version=port.version,
        severity="High",
        description="Anonymous FTP access is enabled.",
        recommendation="Disable anonymous FTP access and use SFTP or FTPS.",
        points=15,
        source="nse",
    )


def check_smb_protocols(port, output):
    output = output.lower()

    if "smbv1" not in output and "smb1" not in output:
        return None

    return Finding(
        service="microsoft-ds",
        port=port.number,
        product=port.product,
        version=port.version,
        severity="High",
        description="SMBv1 is enabled.",
        recommendation="Disable SMBv1 and use SMBv2 or SMBv3.",
        points=15,
        source="nse",
    )


def check_smb_security(port, output):
    output = output.lower()

    if "signing: disabled" not in output:
        return None

    return Finding(
        service="microsoft-ds",
        port=port.number,
        product=port.product,
        version=port.version,
        severity="Medium",
        description="SMB message signing is not enforced.",
        recommendation="Enable SMB message signing.",
        points=7,
        source="nse",
    )


def check_http_methods(port, output):
    dangerous_methods = [
        "PUT",
        "DELETE",
        "TRACE",
        "CONNECT",
    ]

    output_upper = output.upper()

    detected = [
        method
        for method in dangerous_methods
        if method in output_upper
    ]

    if not detected:
        return None

    return Finding(
        service=port.service,
        port=port.number,
        product=port.product,
        version=port.version,
        severity="Medium",
        description=(
            "Potentially dangerous HTTP methods are enabled: "
            + ", ".join(detected)
        ),
        recommendation=(
            "Disable unnecessary HTTP methods and allow "
            "only required methods."
        ),
        points=7,
        source="nse",
    )


NSE_CHECKS = {
    "ftp-anon": check_ftp_anonymous,
    "smb-protocols": check_smb_protocols,
    "smb-security-mode": check_smb_security,
    "http-methods": check_http_methods,
}


def analyze_nse(device):
    findings = []

    for port in device.ports:

        if not hasattr(port, "nse_output"):
            continue

        for script_id, output in port.nse_output.items():

            checker = NSE_CHECKS.get(script_id)

            if not checker:
                continue

            result = checker(port, output)

            if result:
                findings.append(result)

    return findings