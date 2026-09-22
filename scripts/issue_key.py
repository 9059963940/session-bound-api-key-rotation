import requests

BASE = "http://127.0.0.1:8000"

r = requests.post(
    BASE + "/admin/issue-key",
    json={"service_name": "authorized-service"},
    timeout=5
)
r.raise_for_status()
data = r.json()

print("\nNEW SESSION-BOUND KEY")
print("Key ID     :", data["key_id"])
print("Session ID :", data["session_id"])
print("API Key    :", data["api_key"])
print("\nCopy the API key into scripts/normal_traffic.py and scripts/simulate_attack.py")
