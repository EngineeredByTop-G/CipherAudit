# CipherAudit — TLS & PKI Certificate Compliance Scanner

> Automated TLS certificate auditing tool for financial institutions — evaluates domains against NIST SP 800-52 and PCI-DSS v4.0, scores risk severity, and generates structured PDF compliance reports.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Standards](https://img.shields.io/badge/Standards-NIST%20SP%20800--52%20%7C%20PCI--DSS%20v4.0-orange)

---

## What It Does

Financial institutions manage hundreds of TLS certificates across public-facing domains. Manual auditing at scale is not feasible. CipherAudit automates the entire audit pipeline:

1. Connects to each domain on port 443 and performs a TLS handshake
2. Extracts certificate metadata — expiry date, issuer, SANs, serial number
3. Detects TLS protocol version and cipher suite in use
4. Scores each domain: **CRITICAL / HIGH / MEDIUM / LOW**
5. Persists all findings to a local SQLite database
6. Generates a structured PDF compliance report

---

## Demo

```
python main.py --domains jpmorganchase.com hsbc.com barclays.com goldmansachs.com
```

```
┌──────────────────────────────┬────────────┬────────────┬───────────┬──────────────────┐
│ Domain                       │  Severity  │  Days Left │    TLS    │ Issuer           │
├──────────────────────────────┼────────────┼────────────┼───────────┼──────────────────┤
│ jpmorganchase.com            │    LOW     │        245 │  TLSv1.3  │ DigiCert Inc     │
│ hsbc.com                     │    LOW     │        315 │  TLSv1.2  │ DigiCert Inc     │
│ barclays.com                 │    LOW     │        182 │  TLSv1.3  │ DigiCert Inc     │
│ goldmansachs.com             │   MEDIUM   │         45 │  TLSv1.3  │ DigiCert Inc     │
└──────────────────────────────┴────────────┴────────────┴───────────┴──────────────────┘

Summary — CRITICAL: 0  HIGH: 0  MEDIUM: 1  LOW: 3
PDF report saved to: output/CipherAudit_Report_20260330.pdf
```

---

## Severity Classification

| Severity | Condition | Action |
|---|---|---|
| CRITICAL | Certificate expired OR weak cipher in use | Immediate remediation |
| HIGH | Expires in < 30 days OR TLS 1.0/1.1 in use | Urgent renewal |
| MEDIUM | Expires in 30–90 days | Schedule renewal |
| LOW | Valid, TLS 1.2+, strong cipher | No action required |

---

## Architecture

```
CipherAudit/
├── scanner.py      # TLS handshake, certificate extraction (ssl + socket)
├── analyser.py     # Risk scoring against NIST/PCI-DSS rules
├── database.py     # SQLite persistence layer
├── report.py       # ReportLab PDF generation
├── main.py         # Orchestrator — ThreadPoolExecutor batch scanning
├── targets.txt     # 50 financial institution domains
└── output/         # Generated PDF reports
```

**Modules communicate via function calls and a shared SQLite database. No external servers required.**

---

## PDF Report Structure

Each generated report contains:
- **Cover page** — scan metadata and severity summary counts
- **Executive Summary** — all domains in a colour-coded severity table
- **Per-Domain Findings** — full certificate details, TLS version, cipher suite, compliance notes
- **Compliance Appendix** — specific NIST SP 800-52 and PCI-DSS v4.0 clause references

---

## Tech Stack

| Component | Technology |
|---|---|
| TLS Connection | Python built-in `ssl` + `socket` |
| Certificate Parsing | `pyOpenSSL`, `cryptography` |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Database | SQLite (built-in, no server needed) |
| Terminal UI | `Rich` (tables, progress bars, colour) |
| PDF Generation | `ReportLab` |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/CipherAudit.git
cd CipherAudit

# 2. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
source venv/bin/activate    # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Scan all domains in targets.txt (50 financial institutions)
python main.py

# Scan specific domains inline
python main.py --domains google.com hsbc.com barclays.com

# Use a custom targets file
python main.py --targets my_domains.txt

# Skip PDF report
python main.py --no-report

# Enable verbose logging
python main.py --verbose
```

---

## Compliance Standards

- **NIST SP 800-52 Rev 2** — Guidelines for TLS Implementations (Sections 3.1, 3.3.1, 3.4, 4.1, 4.2)
- **PCI-DSS v4.0** — Requirements 4.2.1, 6.3.3, 12.3.3, 12.3.4

---

## Author

**Gowtham Gowda**
**MSc Computer Networking & Cybersecurity**
London Metropolitan University

---

*Part of a 5-project cybersecurity portfolio targeting financial institution security roles.*
