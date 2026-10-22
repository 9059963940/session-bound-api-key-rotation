
import hashlib
import os
import sqlite3

import requests

from app.config import DB_PATH

BASE_URL = "http://127.0.0.1:8000"

ADMIN_HEADERS = {
    "X-Admin-Token": os.environ["ADMIN_TOKEN"]
}


def test_health():
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200


def test_issue_api_key():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "api_key" in data

def test_issue_key_rejects_empty_service_name():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": ""},
    )

    assert response.status_code == 422


def test_issue_key_rejects_whitespace_service_name():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "   "},
    )

    assert response.status_code == 422


def test_issue_key_rejects_service_name_over_100_characters():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "a" * 101},
    )

    assert response.status_code == 422


def test_issue_key_trims_service_name_whitespace():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "  test-service  "},
    )

    assert response.status_code == 200
    assert response.json()["service_name"] == "test-service"


def test_fresh_api_key_can_access_secure_data():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert issue_response.status_code == 200
    api_key = issue_response.json()["api_key"]

    secure_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": api_key},
    )

    assert secure_response.status_code == 200


def test_fresh_api_key_handles_normal_traffic():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert issue_response.status_code == 200
    api_key = issue_response.json()["api_key"]
    headers = {"X-API-Key": api_key}

    successful_requests = 0

    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers=headers,
        )

        assert response.status_code == 200
        successful_requests += 1

    assert successful_requests == 30


def test_anomalous_traffic_triggers_rotation():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert response.status_code == 200
    old_key = response.json()["api_key"]
    old_key_id = response.json()["key_id"]
    headers = {"X-API-Key": old_key}

    # Establish the normal behavioral baseline.
    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers=headers,
        )
        assert response.status_code == 200

    # Send anomalous traffic.
    anomalous_headers = {
        "X-API-Key": old_key,
        "User-Agent": "AnomalousSecurityScanner/1.0",
    }

    response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers=anomalous_headers,
    )

    assert response.status_code == 200

    # Confirm automatic rotation.
    rotations_response = requests.get(
        f"{BASE_URL}/admin/rotations",
        headers=ADMIN_HEADERS,
    )

    assert rotations_response.status_code == 200
    rotations = [
        item for item in rotations_response.json()["rotations"]
        if item.get("old_key_id") == old_key_id
    ]
    assert len(rotations) == 1

    latest_rotation = rotations[0]
    assert latest_rotation["old_key_id"] is not None
    assert latest_rotation["new_key_id"] is not None


def test_rotation_revokes_old_key_and_activates_new_key():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert response.status_code == 200
    old_key = response.json()["api_key"]
    old_key_id = response.json()["key_id"]

    # Build the normal behavioral baseline.
    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={"X-API-Key": old_key},
        )
        assert response.status_code == 200

    # Trigger anomalous behavior.
    response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": old_key,
            "User-Agent": "AnomalousSecurityScanner/1.0",
        },
    )

    assert response.status_code == 200

    rotations_response = requests.get(
        f"{BASE_URL}/admin/rotations",
        headers=ADMIN_HEADERS,
    )

    assert rotations_response.status_code == 200
    rotations = [
        item for item in rotations_response.json()["rotations"]
        if item.get("old_key_id") == old_key_id
    ]
    assert len(rotations) == 1

    new_key_id = rotations[0]["new_key_id"]
    assert new_key_id is not None

    # Confirm old key is no longer usable.
    old_key_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": old_key},
    )
    assert old_key_response.status_code == 401

    # Find the newly generated key.
    keys_response = requests.get(
        f"{BASE_URL}/admin/keys",
        headers=ADMIN_HEADERS,
    )

    assert keys_response.status_code == 200
    keys = keys_response.json()["keys"]

    new_key_record = next(
        (key for key in keys if key["key_id"] == new_key_id),
        None,
    )

    assert new_key_record is not None
    assert new_key_record["active"] in (1, True)


def test_missing_api_key_is_rejected():
    response = requests.get(f"{BASE_URL}/api/secure-data")
    assert response.status_code == 401


def test_invalid_api_key_is_rejected():
    response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": "sb_invalid_test_key"},
    )
    assert response.status_code == 401


def test_old_key_is_rejected_after_rotation():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert issue_response.status_code == 200
    old_key = issue_response.json()["api_key"]
    old_key_id = issue_response.json()["key_id"]

    # Establish baseline.
    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={"X-API-Key": old_key},
        )
        assert response.status_code == 200

    # Trigger rotation.
    response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": old_key,
            "User-Agent": "AnomalousSecurityScanner/1.0",
        },
    )
    assert response.status_code == 200

    rotation_data = requests.get(
        f"{BASE_URL}/admin/rotations",
        headers=ADMIN_HEADERS,
    )

    assert rotation_data.status_code == 200
    rotations = [
        item for item in rotation_data.json()["rotations"]
        if item.get("old_key_id") == old_key_id
    ]
    assert len(rotations) == 1

    # Old credential must now be rejected.
    revoked_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": old_key},
    )
    assert revoked_response.status_code == 401


def test_rotation_cooldown_prevents_immediate_second_rotation():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert issue_response.status_code == 200
    old_key = issue_response.json()["api_key"]
    old_key_id = issue_response.json()["key_id"]

    # Establish the normal baseline.
    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={"X-API-Key": old_key},
        )
        assert response.status_code == 200

    # First anomalous request triggers rotation.
    first_anomaly = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": old_key,
            "User-Agent": "AnomalousSecurityScanner/1.0",
        },
    )

    assert first_anomaly.status_code == 200
    first_security = first_anomaly.json()["security"]
    assert first_security["rotated"] is True

    rotations_after_first = requests.get(
        f"{BASE_URL}/admin/rotations",
        headers=ADMIN_HEADERS,
    )

    assert rotations_after_first.status_code == 200
    first_rotations = [
        item for item in rotations_after_first.json()["rotations"]
        if item.get("old_key_id") == old_key_id
    ]
    first_rotation_count = len(first_rotations)
    assert first_rotation_count == 1

    # The old key should now be revoked.
    revoked_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": old_key},
    )
    assert revoked_response.status_code == 401

    # No second rotation should be created immediately.
    rotations_after_second_check = requests.get(
        f"{BASE_URL}/admin/rotations",
        headers=ADMIN_HEADERS,
    )

    assert rotations_after_second_check.status_code == 200
    second_rotations = [
        item for item in rotations_after_second_check.json()["rotations"]
        if item.get("old_key_id") == old_key_id
    ]
    second_rotation_count = len(second_rotations)

    assert second_rotation_count == first_rotation_count


def test_new_key_can_access_secure_data_after_rotation():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert issue_response.status_code == 200
    old_key = issue_response.json()["api_key"]

    # Establish normal behavioral baseline.
    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={"X-API-Key": old_key},
        )
        assert response.status_code == 200

    # Trigger automatic rotation.
    anomaly_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": old_key,
            "User-Agent": "AnomalousSecurityScanner/1.0",
        },
    )

    assert anomaly_response.status_code == 200
    security = anomaly_response.json()["security"]

    assert security["rotated"] is True
    assert "new_api_key" in security

    new_api_key = security["new_api_key"]
    assert new_api_key

    # The newly generated key must work.
    new_key_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": new_api_key},
    )
    assert new_key_response.status_code == 200

    # Verify replacement key and session.
    new_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": new_api_key},
    )

    assert new_response.status_code == 200
    assert (
        new_response.json()["session_id"]
        == security["new_session_id"]
    )

    # Verify the original key has been revoked.
    revoked_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={"X-API-Key": old_key},
    )
    assert revoked_response.status_code == 401


def test_api_key_is_stored_as_sha256_hash():
    # Issue a fresh API key.
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        headers=ADMIN_HEADERS,
        json={"service_name": "authorized-service"},
    )

    assert response.status_code == 200
    api_key = response.json()["api_key"]

    # Calculate the expected SHA-256 hash.
    expected_hash = hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()

    # Verify the database stores the hash, not the original key.
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT api_key FROM api_keys WHERE api_key = ?",
            (expected_hash,),
        ).fetchone()

    assert row is not None, (
        "Hashed API key was not found in the database"
    )
    assert row[0] == expected_hash
    assert row[0] != api_key




def test_admin_endpoint_rejects_missing_admin_token():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={"service_name": "test-service"},
    )

    assert response.status_code == 401


def test_admin_endpoint_rejects_invalid_admin_token():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={"service_name": "test-service"},
        headers={
            "X-Admin-Token": "definitely-not-the-correct-token"
        },
    )

    assert response.status_code == 401
