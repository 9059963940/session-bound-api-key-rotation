import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # ========================================================
    # API KEYS TABLE
    # ========================================================

    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY,
        api_key TEXT UNIQUE NOT NULL,
        service_name TEXT NOT NULL,
        session_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        revoked_at TEXT,
        active INTEGER NOT NULL DEFAULT 1
    )
    """)

    # ========================================================
    # API REQUESTS TABLE
    # ========================================================

    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        payload_size INTEGER NOT NULL,
        client_ip TEXT NOT NULL,
        client_fingerprint TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        latency_ms REAL NOT NULL
    )
    """)

    # ========================================================
    # ROTATIONS TABLE
    # ========================================================

    cur.execute("""
    CREATE TABLE IF NOT EXISTS rotations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        old_key_id TEXT NOT NULL,
        new_key_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        risk_score REAL NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # ========================================================
    # DATABASE MIGRATION
    #
    # Existing databases already have api_requests.
    # These ALTER TABLE statements add the new security
    # columns without deleting existing request history.
    # ========================================================

    existing_columns = {
        row["name"]
        for row in cur.execute(
            "PRAGMA table_info(api_requests)"
        ).fetchall()
    }

    if "anomaly_score" not in existing_columns:
        cur.execute("""
            ALTER TABLE api_requests
            ADD COLUMN anomaly_score REAL
        """)

    if "risk_score" not in existing_columns:
        cur.execute("""
            ALTER TABLE api_requests
            ADD COLUMN risk_score REAL
        """)

    if "security_reason" not in existing_columns:
        cur.execute("""
            ALTER TABLE api_requests
            ADD COLUMN security_reason TEXT
        """)

    if "rotated" not in existing_columns:
        cur.execute("""
            ALTER TABLE api_requests
            ADD COLUMN rotated INTEGER NOT NULL DEFAULT 0
        """)

    conn.commit()
    conn.close()


# ============================================================
# API KEY FUNCTIONS
# ============================================================

def insert_key(key_id, api_key, service_name, session_id):
    conn = get_conn()

    conn.execute(
        """
        INSERT INTO api_keys
        (key_id, api_key, service_name, session_id, created_at,
         revoked_at, active)
        VALUES (?, ?, ?, ?, ?, NULL, 1)
        """,
        (
            key_id,
            api_key,
            service_name,
            session_id,
            now_iso()
        )
    )

    conn.commit()
    conn.close()


def get_key(api_key):
    conn = get_conn()

    row = conn.execute(
        """
        SELECT *
        FROM api_keys
        WHERE api_key = ?
        AND active = 1
        """,
        (api_key,)
    ).fetchone()

    conn.close()

    return row


def revoke_key(key_id):
    conn = get_conn()

    conn.execute(
        """
        UPDATE api_keys
        SET active = 0,
            revoked_at = ?
        WHERE key_id = ?
        """,
        (
            now_iso(),
            key_id
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# REQUEST FUNCTIONS
# ============================================================

def insert_request(data):
    conn = get_conn()

    cursor = conn.execute(
        """
        INSERT INTO api_requests
        (
            key_id,
            timestamp,
            endpoint,
            method,
            payload_size,
            client_ip,
            client_fingerprint,
            status_code,
            latency_ms,
            anomaly_score,
            risk_score,
            security_reason,
            rotated
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["key_id"],
            data["timestamp"],
            data["endpoint"],
            data["method"],
            data["payload_size"],
            data["client_ip"],
            data["client_fingerprint"],
            data["status_code"],
            data["latency_ms"],
            data.get("anomaly_score"),
            data.get("risk_score"),
            data.get("security_reason"),
            data.get("rotated", 0)
        )
    )

    request_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return request_id


def update_request_security(
    request_id,
    anomaly_score,
    risk_score,
    security_reason,
    rotated=False
):
    conn = get_conn()

    conn.execute(
        """
        UPDATE api_requests
        SET anomaly_score = ?,
            risk_score = ?,
            security_reason = ?,
            rotated = ?
        WHERE id = ?
        """,
        (
            anomaly_score,
            risk_score,
            security_reason,
            1 if rotated else 0,
            request_id
        )
    )

    conn.commit()
    conn.close()


def recent_requests(key_id, limit=200):
    conn = get_conn()

    rows = conn.execute(
        """
        SELECT *
        FROM api_requests
        WHERE key_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (
            key_id,
            limit
        )
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in reversed(rows)
    ]


def all_requests(limit=500):
    conn = get_conn()

    rows = conn.execute(
        """
        SELECT *
        FROM api_requests
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# ROTATION FUNCTIONS
# ============================================================

def insert_rotation(
    old_key_id,
    new_key_id,
    session_id,
    reason,
    risk_score
):
    conn = get_conn()

    conn.execute(
        """
        INSERT INTO rotations
        (
            old_key_id,
            new_key_id,
            session_id,
            reason,
            risk_score,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            old_key_id,
            new_key_id,
            session_id,
            reason,
            risk_score,
            now_iso()
        )
    )

    conn.commit()
    conn.close()


def update_latest_rotation_score(score):
    conn = get_conn()

    conn.execute(
        """
        UPDATE rotations
        SET risk_score = ?
        WHERE id = (
            SELECT MAX(id)
            FROM rotations
        )
        """,
        (score,)
    )

    conn.commit()
    conn.close()


def all_rotations(limit=100):
    conn = get_conn()

    rows = conn.execute(
        """
        SELECT *
        FROM rotations
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# API KEY LIST
# ============================================================

def all_keys():
    conn = get_conn()

    rows = conn.execute(
        """
        SELECT
            key_id,
            service_name,
            session_id,
            created_at,
            revoked_at,
            active
        FROM api_keys
        ORDER BY created_at DESC
        """
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]