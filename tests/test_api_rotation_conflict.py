
from fastapi.testclient import TestClient

from app import main


def test_rotation_conflict_returns_409(monkeypatch):
    # Simulate a valid API key.
    fake_key = {
        "key_id": "test-key-id",
        "service_name": "test-service",
        "session_id": "test-session",
    }

    monkeypatch.setattr(
        main,
        "get_key",
        lambda api_key: fake_key,
    )

    # Simulate storing the incoming request.
    monkeypatch.setattr(
        main,
        "insert_request",
        lambda data: 123,
    )

    # Force the anomaly detector to report high risk.
    class FakeDetector:
        def observe(self, key_id):
            return {
                "ready": True,
                "risk_score": 0.95,
                "anomaly_score": 0.95,
                "reason": "Test rotation conflict",
            }

    monkeypatch.setattr(main, "detector", FakeDetector())

    # Simulate a rotation conflict.
    class FakeRotator:
        def should_rotate(self, key_id, risk_score, threshold):
            return True

        def rotate(self, key, risk_score):
            raise RuntimeError(
                "Old API key is missing or already revoked"
            )

    monkeypatch.setattr(main, "rotator", FakeRotator())

    # Capture the failed-rotation security record.
    recorded_updates = []

    def fake_update_request_security(**kwargs):
        recorded_updates.append(kwargs)

    monkeypatch.setattr(
        main,
        "update_request_security",
        fake_update_request_security,
    )

    client = TestClient(main.app)

    response = client.get(
        "/api/secure-data",
        headers={"X-API-Key": "test-api-key"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "API key rotation conflicted with another request. "
        "Retry with a current API key."
    )

    assert len(recorded_updates) == 1
    assert recorded_updates[0]["request_id"] == 123
    assert recorded_updates[0]["rotated"] is False
    assert recorded_updates[0]["security_reason"] == (
        "Rotation rejected because the API key "
        "was already revoked or rotated"
    )
