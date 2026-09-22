import requests


BASE_URL = "http://127.0.0.1:8000"


def test_health():
    response = requests.get(
        f"{BASE_URL}/health"
    )

    assert response.status_code == 200


def test_issue_api_key():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={
            "service_name": "authorized-service"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "api_key" in data


def test_fresh_api_key_can_access_secure_data():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={
            "service_name": "authorized-service"
        },
    )

    assert issue_response.status_code == 200

    data = issue_response.json()

    api_key = data["api_key"]

    secure_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": api_key
        },
    )

    assert secure_response.status_code == 200


def test_fresh_api_key_handles_normal_traffic():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={
            "service_name": "authorized-service"
        },
    )

    assert issue_response.status_code == 200

    data = issue_response.json()

    api_key = data["api_key"]

    headers = {
        "X-API-Key": api_key
    }

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
        json={
            "service_name": "authorized-service"
        },
    )

    assert response.status_code == 200

    data = response.json()

    old_key = data["api_key"]

    headers = {
        "X-API-Key": old_key
    }

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
        f"{BASE_URL}/admin/rotations"
    )

    assert rotations_response.status_code == 200

    rotations = rotations_response.json()["rotations"]

    assert len(rotations) > 0

    latest_rotation = rotations[0]

    assert latest_rotation["old_key_id"] is not None
    assert latest_rotation["new_key_id"] is not None


def test_rotation_revokes_old_key_and_activates_new_key():
    response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={
            "service_name": "authorized-service"
        },
    )

    assert response.status_code == 200

    data = response.json()

    old_key = data["api_key"]

    # Build the normal behavioral baseline.
    for _ in range(30):

        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={
                "X-API-Key": old_key
            },
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

    # Confirm that a rotation was recorded.
    rotations_response = requests.get(
        f"{BASE_URL}/admin/rotations"
    )

    assert rotations_response.status_code == 200

    rotations = rotations_response.json()["rotations"]

    assert len(rotations) > 0

    latest_rotation = rotations[0]

    new_key_id = latest_rotation["new_key_id"]

    assert new_key_id is not None

    # Confirm old key is no longer usable.
    old_key_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": old_key
        },
    )

    assert old_key_response.status_code == 401

    # Find the newly generated key.
    keys_response = requests.get(
        f"{BASE_URL}/admin/keys"
    )

    assert keys_response.status_code == 200

    keys = keys_response.json()["keys"]

    new_key_record = next(
        (
            key
            for key in keys
            if key["key_id"] == new_key_id
        ),
        None,
    )

    assert new_key_record is not None

    assert new_key_record["active"] in (1, True)


def test_missing_api_key_is_rejected():
    response = requests.get(
        f"{BASE_URL}/api/secure-data"
    )

    assert response.status_code == 401


def test_invalid_api_key_is_rejected():
    response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": "sb_invalid_test_key"
        },
    )

    assert response.status_code == 401


def test_old_key_is_rejected_after_rotation():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={
            "service_name": "authorized-service"
        },
    )

    assert issue_response.status_code == 200

    old_key = issue_response.json()["api_key"]

    # Establish baseline.
    for _ in range(30):

        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={
                "X-API-Key": old_key
            },
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
        f"{BASE_URL}/admin/rotations"
    )

    assert rotation_data.status_code == 200

    rotations = rotation_data.json()["rotations"]

    assert len(rotations) > 0

    # Old credential must now be rejected.
    revoked_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": old_key
        },
    )

    assert revoked_response.status_code == 401
def test_rotation_cooldown_prevents_immediate_second_rotation():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={
            "service_name": "authorized-service"
        },
    )

    assert issue_response.status_code == 200

    old_key = issue_response.json()["api_key"]

    # Establish the normal baseline.
    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={
                "X-API-Key": old_key
            },
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
        f"{BASE_URL}/admin/rotations"
    )

    assert rotations_after_first.status_code == 200

    first_rotation_count = len(
        rotations_after_first.json()["rotations"]
    )

    assert first_rotation_count > 0

    # The old key should now be revoked.
    revoked_response = requests.get(
        f"{BASE_URL}/api/secure-data",
        headers={
            "X-API-Key": old_key
        },
    )

    assert revoked_response.status_code == 401

    # No second rotation should be created immediately.
    rotations_after_second_check = requests.get(
        f"{BASE_URL}/admin/rotations"
    )

    assert rotations_after_second_check.status_code == 200

    second_rotation_count = len(
        rotations_after_second_check.json()["rotations"]
    )

    assert second_rotation_count == first_rotation_count

def test_new_key_can_access_secure_data_after_rotation():
    issue_response = requests.post(
        f"{BASE_URL}/admin/issue-key",
        json={
            "service_name": "authorized-service"
        },
    )

    assert issue_response.status_code == 200

    old_key = issue_response.json()["api_key"]

    # Establish normal behavioral baseline.
    for _ in range(30):
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers={
                "X-API-Key": old_key
            },
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
        headers={
            "X-API-Key": new_api_key
        },
    )

    assert new_key_response.status_code == 200