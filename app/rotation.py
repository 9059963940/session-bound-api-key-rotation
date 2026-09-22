import time
from .key_vault import KeyVault
from .database import insert_rotation
from .config import ROTATION_COOLDOWN_SECONDS

class RotationController:
    def __init__(self):
        self.vault = KeyVault()
        self.last_rotation = {}

    def should_rotate(self, key_id, risk_score, threshold):
        last = self.last_rotation.get(key_id, 0)
        return (
            risk_score >= threshold and
            time.time() - last > ROTATION_COOLDOWN_SECONDS
        )

    def rotate(self, old_key, risk_score):
        new_key = self.vault.generate_session_key(old_key["service_name"])
        self.vault.revoke(old_key["key_id"])
        self.last_rotation[old_key["key_id"]] = time.time()

        insert_rotation(
            old_key["key_id"],
            new_key["key_id"],
            new_key["session_id"],
            "Behavioral anomaly exceeded risk threshold",
            risk_score
        )
        return new_key
