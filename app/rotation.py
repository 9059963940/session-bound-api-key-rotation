
import secrets
import uuid
from datetime import datetime, timezone

from .database import (
    get_last_rotation_time,
    rotate_key_transaction,
)
from .config import ROTATION_COOLDOWN_SECONDS


class RotationController:
    def should_rotate(self, key_id, risk_score, threshold):
        if risk_score < threshold:
            return False

        last_rotation = get_last_rotation_time(key_id)

        if last_rotation is None:
            return True

        last_time = datetime.fromisoformat(last_rotation)

        if last_time.tzinfo is None:
            last_time = last_time.replace(tzinfo=timezone.utc)

        elapsed = (
            datetime.now(timezone.utc) - last_time
        ).total_seconds()

        return elapsed > ROTATION_COOLDOWN_SECONDS

    def rotate(self, old_key, risk_score):
        new_key_id = str(uuid.uuid4())
        new_session_id = str(uuid.uuid4())
        new_api_key = "sb_" + secrets.token_urlsafe(32)

        rotate_key_transaction(
            old_key_id=old_key["key_id"],
            new_key_id=new_key_id,
            new_api_key=new_api_key,
            service_name=old_key["service_name"],
            new_session_id=new_session_id,
            reason="Behavioral anomaly exceeded risk threshold",
            risk_score=risk_score,
        )

        return {
            "key_id": new_key_id,
            "api_key": new_api_key,
            "session_id": new_session_id,
            "service_name": old_key["service_name"],
        }
