"""
database.py — Persistence Layer
CipherAudit | TLS & PKI Certificate Compliance Scanner

Technology: SQLite (built into Python — no server needed)
Database file: cipheraudit.db (auto-created on first run)

Schema (single table: scans):
  id           INTEGER PRIMARY KEY AUTOINCREMENT
  hostname     TEXT NOT NULL
  scan_date    TEXT NOT NULL        -- ISO 8601 UTC timestamp
  expiry_date  TEXT                 -- ISO 8601 or NULL
  days_left    INTEGER
  tls_version  TEXT
  cipher_suite TEXT
  issuer       TEXT
  severity     TEXT
  notes        TEXT
"""

import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "cipheraudit.db"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname     TEXT    NOT NULL,
    scan_date    TEXT    NOT NULL,
    expiry_date  TEXT,
    days_left    INTEGER,
    tls_version  TEXT,
    cipher_suite TEXT,
    issuer       TEXT,
    severity     TEXT,
    notes        TEXT
);
"""

CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans (hostname);
"""


def init_db(db_path: Path = DB_PATH) -> None:
    """Create the database and scans table if they don't already exist."""
    with _connect(db_path) as conn:
        conn.execute(CREATE_TABLE_SQL)
        conn.execute(CREATE_INDEX_SQL)
    logger.debug("Database initialised at %s", db_path)


def save_result(analysis: dict, db_path: Path = DB_PATH) -> int:
    """
    Insert one analysis result into the scans table.
    Returns the row id of the inserted record.
    """
    scan_date = datetime.now(tz=timezone.utc).isoformat()

    row = (
        analysis.get("hostname"),
        scan_date,
        analysis.get("expiry_date"),
        analysis.get("days_left"),
        analysis.get("tls_version"),
        analysis.get("cipher_suite"),
        analysis.get("issuer"),
        analysis.get("severity"),
        analysis.get("notes"),
    )

    sql = """
        INSERT INTO scans
            (hostname, scan_date, expiry_date, days_left,
             tls_version, cipher_suite, issuer, severity, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    with _connect(db_path) as conn:
        cursor = conn.execute(sql, row)
        row_id = cursor.lastrowid

    logger.debug("Saved scan result for %s (id=%d)", analysis.get("hostname"), row_id)
    return row_id


def save_failed(hostname: str, db_path: Path = DB_PATH) -> int:
    """
    Insert a placeholder row for a host that could not be reached.
    Marks severity as UNKNOWN so it appears in the report.
    """
    scan_date = datetime.now(tz=timezone.utc).isoformat()

    row = (
        hostname,
        scan_date,
        None, None, None, None, None,
        "UNKNOWN",
        "Scan failed — host unreachable or no TLS certificate returned",
    )

    sql = """
        INSERT INTO scans
            (hostname, scan_date, expiry_date, days_left,
             tls_version, cipher_suite, issuer, severity, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    with _connect(db_path) as conn:
        cursor = conn.execute(sql, row)
        return cursor.lastrowid


def get_latest_scan(db_path: Path = DB_PATH) -> list[dict]:
    """
    Return the most recent scan result for each distinct hostname,
    ordered by severity (CRITICAL first) then hostname.
    """
    sql = """
        SELECT s.*
        FROM scans s
        INNER JOIN (
            SELECT hostname, MAX(scan_date) AS latest
            FROM scans
            GROUP BY hostname
        ) latest_scans
        ON s.hostname = latest_scans.hostname
        AND s.scan_date = latest_scans.latest
        ORDER BY
            CASE s.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END,
            s.hostname
    """
    with _connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()
    return [dict(row) for row in rows]


def get_all_scans(db_path: Path = DB_PATH) -> list[dict]:
    """Return every row in the scans table, newest first."""
    sql = "SELECT * FROM scans ORDER BY scan_date DESC"
    with _connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()
    return [dict(row) for row in rows]


def get_severity_summary(db_path: Path = DB_PATH) -> dict:
    """
    Return a count of the latest scan result per severity tier.
    e.g. {'CRITICAL': 3, 'HIGH': 7, 'MEDIUM': 12, 'LOW': 28, 'UNKNOWN': 2}
    """
    rows = get_latest_scan(db_path)
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for row in rows:
        sev = row.get("severity", "UNKNOWN") or "UNKNOWN"
        summary[sev] = summary.get(sev, 0) + 1
    return summary


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _connect(db_path: Path) -> sqlite3.Connection:
    """Return a connection with WAL mode and foreign keys enabled."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


# ---------------------------------------------------------------------------
# Quick standalone test — run: python database.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")

    init_db()
    print(f"Database created at: {DB_PATH}")

    # Insert a test record
    test_result = {
        "hostname":     "test.example.com",
        "expiry_date":  "2025-12-31T00:00:00+00:00",
        "days_left":    90,
        "tls_version":  "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "issuer":       "DigiCert Inc",
        "severity":     "MEDIUM",
        "notes":        "Certificate expires in 90 days — schedule renewal",
    }
    row_id = save_result(test_result)
    print(f"Inserted test record with id={row_id}")

    # Retrieve and display
    rows = get_latest_scan()
    print(f"\nLatest scans ({len(rows)} rows):")
    for row in rows:
        print(f"  [{row['severity']:8}] {row['hostname']} — {row['notes']}")

    summary = get_severity_summary()
    print(f"\nSeverity summary: {summary}")
