import secrets
import uuid
from .database import insert_key, revoke_key

class KeyVault:
    """Local simulated key vault for the academic prototype."""

    def generate_session_key(self, service_name):
        key_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        api_key = "sb_" + secrets.token_urlsafe(32)
        insert_key(key_id, api_key, service_name, session_id)
        return {
            "key_id": key_id,
            "api_key": api_key,
            "session_id": session_id,
            "service_name": service_name,
        }

    def revoke(self, key_id):
        revoke_key(key_id)
