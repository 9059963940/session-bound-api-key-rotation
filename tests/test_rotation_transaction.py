import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import threading
import pytest

from app import database


def test_rotation_rolls_back_if_new_key_insert_fails(
    tmp_path,
    monkeypatch,
):
    # Use an isolated temporary database.
    test_db = tmp_path / "test_security.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)

    database.init_db()

    old_key_id = "old-test-key"
    old_api_key = "sb_old-test-secret"

    database.insert_key(
        old_key_id,
        old_api_key,
        "test-service",
        "old-test-session",
    )

    # Force an insert failure by reusing the existing key ID.
    # This happens after the transaction attempts to revoke the old key.
    with pytest.raises(sqlite3.IntegrityError):
        database.rotate_key_transaction(
            old_key_id=old_key_id,
            new_key_id=old_key_id,
            new_api_key="sb_new-test-secret",
            service_name="test-service",
            new_session_id="new-test-session",
            reason="Test rollback",
            risk_score=0.9,
        )

    # The failed transaction must leave the original key active.
    conn = database.get_conn()
    try:
        old_key = conn.execute(
            """
            SELECT active, revoked_at
            FROM api_keys
            WHERE key_id = ?
            """,
            (old_key_id,),
        ).fetchone()

        rotation_count = conn.execute(
            "SELECT COUNT(*) FROM rotations"
        ).fetchone()[0]

        key_count = conn.execute(
            "SELECT COUNT(*) FROM api_keys"
        ).fetchone()[0]
    finally:
        conn.close()

    assert old_key is not None
    assert old_key["active"] == 1
    assert old_key["revoked_at"] is None
    assert rotation_count == 0
    assert key_count == 1


def test_already_revoked_key_cannot_be_rotated_again(
    tmp_path,
    monkeypatch,
):
    test_db = tmp_path / "test_duplicate_rotation.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)

    database.init_db()

    database.insert_key(
        "old-key",
        "sb_old-secret",
        "test-service",
        "old-session",
    )

    # First rotation should succeed.
    database.rotate_key_transaction(
        old_key_id="old-key",
        new_key_id="new-key-1",
        new_api_key="sb_new-secret-1",
        service_name="test-service",
        new_session_id="new-session-1",
        reason="First rotation",
        risk_score=0.9,
    )

    # A second rotation using the already-revoked key must fail.
    with pytest.raises(
        RuntimeError,
        match="Old API key is missing or already revoked",
    ):
        database.rotate_key_transaction(
            old_key_id="old-key",
            new_key_id="new-key-2",
            new_api_key="sb_new-secret-2",
            service_name="test-service",
            new_session_id="new-session-2",
            reason="Duplicate rotation",
            risk_score=0.95,
        )

    conn = database.get_conn()
    try:
        key_count = conn.execute(
            "SELECT COUNT(*) FROM api_keys"
        ).fetchone()[0]

        rotation_count = conn.execute(
            "SELECT COUNT(*) FROM rotations"
        ).fetchone()[0]

        active_count = conn.execute(
            "SELECT COUNT(*) FROM api_keys WHERE active = 1"
        ).fetchone()[0]
    finally:
        conn.close()

    assert key_count == 2
    assert rotation_count == 1
    assert active_count == 1

def test_concurrent_rotation_allows_only_one_success(
    tmp_path,
    monkeypatch,
):
    test_db = tmp_path / "test_concurrent_rotation.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)

    database.init_db()

    database.insert_key(
        "old-concurrent-key",
        "sb_old-concurrent-secret",
        "test-service",
        "old-session",
    )

    # Ensure both threads start their rotation attempt together.
    start_barrier = threading.Barrier(2)

    def attempt_rotation(new_key_id):
        start_barrier.wait(timeout=5)

        try:
            database.rotate_key_transaction(
                old_key_id="old-concurrent-key",
                new_key_id=new_key_id,
                new_api_key=f"sb_secret-{new_key_id}",
                service_name="test-service",
                new_session_id=f"session-{new_key_id}",
                reason="Concurrent rotation test",
                risk_score=0.9,
            )
            return "success"
        except RuntimeError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                attempt_rotation,
                ["new-key-a", "new-key-b"],
            )
        )

    assert results.count("success") == 1
    assert results.count("rejected") == 1

    conn = database.get_conn()
    try:
        key_count = conn.execute(
            "SELECT COUNT(*) FROM api_keys"
        ).fetchone()[0]

        rotation_count = conn.execute(
            "SELECT COUNT(*) FROM rotations"
        ).fetchone()[0]

        active_count = conn.execute(
            "SELECT COUNT(*) FROM api_keys WHERE active = 1"
        ).fetchone()[0]
    finally:
        conn.close()

    assert key_count == 2
    assert rotation_count == 1
    assert active_count == 1