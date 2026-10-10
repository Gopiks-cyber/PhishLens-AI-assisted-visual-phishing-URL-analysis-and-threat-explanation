"""SQLite persistence layer for PhishLens investigation history.

Stores each completed URL analysis so it can be listed, reopened, and
exported as a PDF evidence report without re-analyzing the URL.

Security notes:
* All SQL uses parameterized queries; no values are interpolated into SQL.
* A fresh connection is opened per operation (no shared mutable state).
* Investigation IDs are random UUID4 strings (unguessable, non-sequential).
* The exact submitted URL is stored for fidelity. Every read path used for
  display redacts embedded credentials (user:pass@) via redact_url_userinfo().
  The analyzer always runs on the raw URL before storage, so redaction never
  affects the analysis itself.
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

DEFAULT_DB_PATH = os.path.join("instance", "phishlens.db")

# Bounds for list queries to avoid unbounded reads.
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


def _utc_now_iso():
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def connect(db_path=None):
    """Open a fresh SQLite connection. The caller is responsible for closing it."""
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_parent_directory(path):
    """Create the parent directory for a database file if it does not exist."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def init_db(db_path=None):
    """Create the investigations table and index if they do not exist."""
    path = db_path or DEFAULT_DB_PATH
    _ensure_parent_directory(path)
    conn = connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_investigations_created
            ON investigations (created_at DESC)
            """
        )
        conn.commit()
    finally:
        conn.close()


def redact_url_userinfo(url):
    """Redact embedded credentials (user:pass@) from a URL for safe display.

    The authority userinfo is replaced with [redacted]. URLs without userinfo
    are returned unchanged. Never raises; on any parse error the original
    string is returned.
    """
    if not isinstance(url, str) or "@" not in url:
        return url
    try:
        parsed = urlparse(url)
        if parsed.username is None and parsed.password is None:
            # "@" present but not as authority userinfo (e.g. in path/query).
            return url
        host_part = parsed.netloc.rsplit("@", 1)[1] if "@" in parsed.netloc else parsed.netloc
        redacted = parsed._replace(netloc="[redacted]@" + host_part)
        return urlunparse(redacted)
    except Exception:
        return url


def is_valid_id(investigation_id):
    """Return True if investigation_id is a valid UUID string."""
    if not isinstance(investigation_id, str):
        return False
    try:
        uuid.UUID(investigation_id)
        return True
    except (ValueError, AttributeError):
        return False


def save_investigation(result, db_path=None):
    """Persist a completed analyzer result. Returns the new investigation ID.

    The result is stored exactly as provided (including the raw URL).
    """
    if not isinstance(result, dict):
        raise TypeError("result must be a dict")

    investigation_id = str(uuid.uuid4())
    created_at = _utc_now_iso()

    url = result.get("url", "")
    if not isinstance(url, str):
        url = ""

    risk_score = result.get("risk_score", 0)
    try:
        risk_score = int(risk_score)
    except (TypeError, ValueError):
        risk_score = 0

    risk_level = str(result.get("risk_level", "error"))
    result_json = json.dumps(result, ensure_ascii=False)

    conn = connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO investigations (id, created_at, url, risk_score, risk_level, result_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (investigation_id, created_at, url, risk_score, risk_level, result_json),
        )
        conn.commit()
    finally:
        conn.close()
    return investigation_id


def list_investigations(limit=DEFAULT_LIST_LIMIT, offset=0, db_path=None):
    """Return a bounded, display-safe list of investigations (newest first).

    The returned ``url`` has embedded credentials redacted.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = DEFAULT_LIST_LIMIT
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0
    limit = max(1, min(limit, MAX_LIST_LIMIT))
    offset = max(0, offset)

    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, created_at, url, risk_score, risk_level
            FROM investigations
            ORDER BY created_at DESC, rowid DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        total_row = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()
        total = int(total_row[0]) if total_row else 0
    finally:
        conn.close()

    investigations = []
    for row in rows:
        item = dict(row)
        item["url"] = redact_url_userinfo(item["url"])
        investigations.append(item)
    return {"investigations": investigations, "total": total}


def get_investigation(investigation_id, db_path=None):
    """Return a single stored investigation, or None if not found / invalid ID.

    Returns a display-safe copy: the submitted URL (both top-level and inside
    the stored result) has embedded credentials redacted. The database retains
    the exact raw URL; the analysis was performed on the raw URL before storage.
    """
    if not is_valid_id(investigation_id):
        return None

    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT id, created_at, url, risk_score, risk_level, result_json
            FROM investigations
            WHERE id = ?
            """,
            (investigation_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    record = dict(row)
    result = json.loads(record.pop("result_json"))
    record["url"] = redact_url_userinfo(record["url"])
    if isinstance(result, dict) and isinstance(result.get("url"), str):
        result["url"] = redact_url_userinfo(result["url"])
    record["result"] = result
    return record
