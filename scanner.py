"""
scanner.py — Network Layer
CipherAudit | TLS & PKI Certificate Compliance Scanner

Responsibilities:
  - Establish TCP connection to target host on port 443
  - Wrap connection in TLS context using Python's built-in ssl module
  - Retrieve raw peer certificate via getpeercert()
  - Detect TLS version and cipher suite via ssock.version() / ssock.cipher()

Input:  hostname (str)  e.g. 'jpmorganchase.com'
Output: dict {
          cert:         raw certificate dict,
          tls_version:  str,
          cipher_suite: str,
          hostname:     str
        }
        Returns None on failure (timeout, connection refused, no cert).
"""

import ssl
import socket
import logging

logger = logging.getLogger(__name__)

# Port and timeout as module-level constants for easy tuning
TARGET_PORT = 443
CONNECT_TIMEOUT = 10  # seconds — per spec


def scan_host(hostname: str) -> dict | None:
    """
    Connect to hostname:443, perform TLS handshake, extract certificate
    metadata and connection details.

    Returns a result dict on success, None on any failure.
    """
    context = _build_ssl_context()

    try:
        with socket.create_connection((hostname, TARGET_PORT), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    logger.warning("[%s] TLS handshake succeeded but no certificate returned", hostname)
                    return None

                tls_version = ssock.version()          # e.g. 'TLSv1.3'
                cipher_info = ssock.cipher()           # (name, protocol, bits)
                cipher_suite = cipher_info[0] if cipher_info else "UNKNOWN"

                return {
                    "hostname":     hostname,
                    "cert":         cert,
                    "tls_version":  tls_version,
                    "cipher_suite": cipher_suite,
                }

    except socket.timeout:
        logger.warning("[%s] Connection timed out after %ds", hostname, CONNECT_TIMEOUT)
    except socket.gaierror as exc:
        logger.warning("[%s] DNS resolution failed: %s", hostname, exc)
    except ConnectionRefusedError:
        logger.warning("[%s] Connection refused on port %d", hostname, TARGET_PORT)
    except ssl.SSLCertVerificationError as exc:
        logger.warning("[%s] SSL certificate verification error: %s", hostname, exc)
    except ssl.SSLError as exc:
        logger.warning("[%s] SSL error: %s", hostname, exc)
    except OSError as exc:
        logger.warning("[%s] OS error: %s", hostname, exc)

    return None


def _build_ssl_context() -> ssl.SSLContext:
    """
    Build an SSL context that:
    - Uses the system/default CA bundle for certificate verification
    - Checks hostname (server name indication)
    - Does NOT restrict protocol versions so we can detect TLS 1.0/1.1 in use
    """
    context = ssl.create_default_context()
    # Allow older TLS versions so we can detect and flag them — don't block them
    context.minimum_version = ssl.TLSVersion.TLSv1
    return context


# ---------------------------------------------------------------------------
# Quick standalone test — run: python scanner.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    test_hosts = sys.argv[1:] or ["jpmorganchase.com", "google.com", "expired.badssl.com"]

    for host in test_hosts:
        print(f"\n{'-' * 60}")
        print(f"  Scanning: {host}")
        print(f"{'-' * 60}")
        result = scan_host(host)
        if result:
            print(f"  TLS Version  : {result['tls_version']}")
            print(f"  Cipher Suite : {result['cipher_suite']}")
            cert = result["cert"]
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            print(f"  Subject CN   : {subject.get('commonName', 'N/A')}")
            print(f"  Issuer       : {issuer.get('organizationName', 'N/A')}")
            print(f"  Expiry       : {cert.get('notAfter', 'N/A')}")
            sans = cert.get("subjectAltName", [])
            print(f"  SANs         : {[v for _, v in sans[:5]]}" + (" ..." if len(sans) > 5 else ""))
        else:
            print(f"  FAILED — no result returned")
