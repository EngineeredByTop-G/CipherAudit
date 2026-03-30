"""
analyser.py — Risk Scoring Layer
CipherAudit | TLS & PKI Certificate Compliance Scanner

Responsibilities:
  - Parse expiry date string to datetime object
  - Calculate days_remaining until certificate expiry
  - Evaluate cipher suite against NIST SP 800-52 / PCI-DSS v4.0 blocklist
  - Evaluate TLS version against allowlist (1.2, 1.3 only)
  - Assign severity: CRITICAL / HIGH / MEDIUM / LOW

Severity Table (per spec):
  CRITICAL  — Certificate expired OR weak cipher in use
  HIGH      — Expires in < 30 days OR TLS 1.0 / 1.1 in use
  MEDIUM    — Expires in 30–90 days
  LOW       — Valid cert, TLS 1.2+, strong cipher
"""

import re
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cipher blocklist — RC4, DES, 3DES, NULL, EXPORT, anonymous (NIST SP 800-52)
# ---------------------------------------------------------------------------
WEAK_CIPHER_PATTERNS = [
    r"RC4",
    r"RC2",
    r"\bDES\b",       # DES but not 3DES  (handled separately)
    r"3DES",
    r"TRIPLE.DES",
    r"NULL",
    r"EXPORT",
    r"anon",
    r"ADH",           # Anonymous Diffie-Hellman
    r"AECDH",         # Anonymous ECDH
    r"MD5",           # MD5-based MACs
]

# TLS versions considered compliant (PCI-DSS v4.0 requires TLS 1.2 minimum)
ALLOWED_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

# Deprecated versions that trigger HIGH severity
DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1"}

# Certificate expiry date format as returned by ssl.getpeercert()
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def analyse(scan_result: dict) -> dict:
    """
    Takes the raw scan result from scanner.py and returns an enriched
    analysis dict with severity, days_left, flags, and notes.

    Input:
        scan_result — dict returned by scanner.scan_host()

    Output dict keys:
        hostname, tls_version, cipher_suite, issuer, expiry_date,
        days_left, severity, weak_cipher, deprecated_tls, notes
    """
    hostname     = scan_result["hostname"]
    cert         = scan_result["cert"]
    tls_version  = scan_result.get("tls_version", "UNKNOWN")
    cipher_suite = scan_result.get("cipher_suite", "UNKNOWN")

    # -- Parse certificate fields ------------------------------------------
    expiry_date   = _parse_expiry(cert.get("notAfter", ""))
    days_left     = _days_remaining(expiry_date)
    issuer        = _extract_field(cert.get("issuer", []), "organizationName")
    subject_cn    = _extract_field(cert.get("subject", []), "commonName")
    serial_number = cert.get("serialNumber", "N/A")
    sans          = [v for _, v in cert.get("subjectAltName", [])]

    # -- Evaluate compliance flags -----------------------------------------
    is_expired      = days_left is not None and days_left < 0
    weak_cipher     = _is_weak_cipher(cipher_suite)
    deprecated_tls  = tls_version in DEPRECATED_TLS_VERSIONS

    # -- Assign severity (spec rule table) ---------------------------------
    severity, notes = _assign_severity(
        is_expired, weak_cipher, deprecated_tls, days_left, cipher_suite, tls_version
    )

    logger.debug("[%s] severity=%s days_left=%s tls=%s cipher=%s",
                 hostname, severity, days_left, tls_version, cipher_suite)

    return {
        "hostname":      hostname,
        "tls_version":   tls_version,
        "cipher_suite":  cipher_suite,
        "issuer":        issuer,
        "subject_cn":    subject_cn,
        "serial_number": serial_number,
        "sans":          sans,
        "expiry_date":   expiry_date.isoformat() if expiry_date else None,
        "days_left":     days_left,
        "severity":      severity,
        "weak_cipher":   weak_cipher,
        "deprecated_tls": deprecated_tls,
        "notes":         notes,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_expiry(not_after: str) -> datetime | None:
    """Parse the notAfter string from ssl.getpeercert() into a UTC datetime."""
    if not not_after:
        return None
    try:
        dt = datetime.strptime(not_after, CERT_DATE_FORMAT)
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        logger.warning("Could not parse expiry date: %r", not_after)
        return None


def _days_remaining(expiry: datetime | None) -> int | None:
    """Return the number of days until expiry (negative = already expired)."""
    if expiry is None:
        return None
    now = datetime.now(tz=timezone.utc)
    return (expiry - now).days


def _is_weak_cipher(cipher_suite: str) -> bool:
    """Return True if the cipher suite matches any entry in the blocklist."""
    upper = cipher_suite.upper()
    for pattern in WEAK_CIPHER_PATTERNS:
        if re.search(pattern, upper, re.IGNORECASE):
            return True
    return False


def _extract_field(rdns: list, field_name: str) -> str:
    """Extract a named field from a list of RDN tuples returned by getpeercert()."""
    for rdn in rdns:
        for key, value in rdn:
            if key == field_name:
                return value
    return "N/A"


def _assign_severity(
    is_expired: bool,
    weak_cipher: bool,
    deprecated_tls: bool,
    days_left: int | None,
    cipher_suite: str,
    tls_version: str,
) -> tuple[str, str]:
    """
    Apply the spec severity rule table and return (severity, notes).
    Rules are evaluated in priority order — highest severity wins.
    """
    notes_parts = []

    # CRITICAL — immediate remediation required
    if is_expired:
        notes_parts.append("Certificate has EXPIRED")
        return "CRITICAL", " | ".join(notes_parts)

    if weak_cipher:
        notes_parts.append(f"Weak/deprecated cipher in use: {cipher_suite}")
        return "CRITICAL", " | ".join(notes_parts)

    # HIGH — urgent action required
    if days_left is not None and days_left < 30:
        notes_parts.append(f"Certificate expires in {days_left} days — urgent renewal required")

    if deprecated_tls:
        notes_parts.append(f"Deprecated TLS version in use: {tls_version} (PCI-DSS requires TLS 1.2+)")

    if notes_parts:
        return "HIGH", " | ".join(notes_parts)

    # MEDIUM — scheduled action required
    if days_left is not None and days_left <= 90:
        notes_parts.append(f"Certificate expires in {days_left} days — schedule renewal")
        return "MEDIUM", " | ".join(notes_parts)

    # LOW — compliant, no action required
    notes_parts.append(f"Valid certificate, {tls_version}, strong cipher — compliant")
    return "LOW", " | ".join(notes_parts)


# ---------------------------------------------------------------------------
# Quick standalone test — run: python analyser.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import logging
    from scanner import scan_host

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    test_hosts = ["jpmorganchase.com", "google.com", "hsbc.com"]
    for host in test_hosts:
        print(f"\n{'─' * 60}")
        raw = scan_host(host)
        if raw:
            result = analyse(raw)
            print(f"  Host         : {result['hostname']}")
            print(f"  Severity     : {result['severity']}")
            print(f"  Days Left    : {result['days_left']}")
            print(f"  TLS Version  : {result['tls_version']}")
            print(f"  Cipher Suite : {result['cipher_suite']}")
            print(f"  Issuer       : {result['issuer']}")
            print(f"  Notes        : {result['notes']}")
        else:
            print(f"  {host} — scan failed")
