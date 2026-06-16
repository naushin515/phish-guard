"""
database.py - SQLite database operations for the Phishing URL Detection System.
Handles all CRUD operations for scan history.
"""

import sqlite3
import os
from datetime import datetime

# Path to the SQLite database file
DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "phishing.db")


def get_connection():
    """Create and return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows dict-like row access
    return conn


def init_db():
    """Initialize the database and create tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            risk_score  INTEGER NOT NULL,
            status      TEXT    NOT NULL,  -- 'Safe', 'Suspicious', 'Phishing'
            reasons     TEXT    NOT NULL,  -- JSON-encoded list of reasons
            scanned_at  TEXT    NOT NULL   -- ISO-8601 datetime string
        )
    """)

    conn.commit()
    conn.close()


def save_scan(url: str, risk_score: int, status: str, reasons: list) -> int:
    """
    Persist a scan result to the database.

    Args:
        url:        The URL that was scanned.
        risk_score: Integer 0-100 representing the risk level.
        status:     Classification string ('Safe', 'Suspicious', 'Phishing').
        reasons:    List of strings explaining the classification.

    Returns:
        The row id of the newly inserted record.
    """
    import json
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scan_history (url, risk_score, status, reasons, scanned_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            url,
            risk_score,
            status,
            json.dumps(reasons),
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )

    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_all_scans() -> list:
    """
    Retrieve all scan records ordered by most recent first.

    Returns:
        List of dicts with keys: id, url, risk_score, status, reasons, scanned_at.
    """
    import json
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scan_history ORDER BY scanned_at DESC"
    )
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        record = dict(row)
        record["reasons"] = json.loads(record["reasons"])
        results.append(record)

    return results


def get_scan_stats() -> dict:
    """
    Return aggregate statistics about all scans performed.

    Returns:
        Dict with total, safe_count, suspicious_count, phishing_count.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'Safe'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'Suspicious'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'Phishing'")
    phishing = cursor.fetchone()[0]

    conn.close()
    return {
        "total": total,
        "safe_count": safe,
        "suspicious_count": suspicious,
        "phishing_count": phishing,
    }


def delete_scan(scan_id: int) -> bool:
    """Delete a single scan record by its id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def clear_all_scans() -> int:
    """Delete every record in the scan history table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    return deleted
