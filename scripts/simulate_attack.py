import sys
import time
import requests

BASE = "http://127.0.0.1:8000"


if len(sys.argv) != 2:
    print("ERROR: API key not provided.")
    print()
    print("Usage:")
    print("python scripts/simulate_attack.py <API_KEY>")
    sys.exit(1)


API_KEY = sys.argv[1]

headers = {
    "X-API-Key": API_KEY,
    "User-Agent": "unknown-attacker-client/9.9",
}


print("=" * 60)
print("SIMULATING SUSPICIOUS TRAFFIC")
print("=" * 60)

rotation_detected = False
new_api_key = None

for i in range(50):

    response = requests.get(
        BASE + "/api/secure-data",
        headers=headers,
        timeout=5,
    )

    print(
        f"{i + 1} | HTTP {response.status_code} | "
        f"{response.text[:500]}"
    )

    # ---------------------------------------------------------
    # Detect automatic rotation
    # ---------------------------------------------------------

    if response.status_code == 200:

        try:
            data = response.json()

            security = data.get("security", {})

            if security.get("rotated") is True:

                rotation_detected = True
                new_api_key = security.get("new_api_key")

                print()
                print("=" * 60)
                print("AUTOMATIC ROTATION DETECTED")
                print("=" * 60)

                print(
                    f"Risk score: "
                    f"{security.get('risk_score')}"
                )

                print(
                    f"Anomaly score: "
                    f"{security.get('anomaly_score')}"
                )

                print(
                    f"Reason: "
                    f"{security.get('reason')}"
                )

                print(
                    f"New session ID: "
                    f"{security.get('new_session_id')}"
                )

                if new_api_key:
                    print("New API key captured successfully.")
                else:
                    print("WARNING: New API key was not returned.")

                break

        except ValueError:
            pass

    # Once the old key is revoked, stop.
    if response.status_code == 401:

        print()
        print("Old API key has been rejected.")
        print("Automatic rotation/revocation has occurred.")

        break

    time.sleep(0.01)


# -------------------------------------------------------------
# VERIFY NEW KEY
# -------------------------------------------------------------

if rotation_detected and new_api_key:

    print()
    print("=" * 60)
    print("VERIFYING NEW API KEY")
    print("=" * 60)

    new_headers = {
        "X-API-Key": new_api_key,
        "User-Agent": "authorized-service-client/1.0",
    }

    new_response = requests.get(
        BASE + "/api/secure-data",
        headers=new_headers,
        timeout=5,
    )

    print(
        f"New key response: HTTP "
        f"{new_response.status_code}"
    )

    print(new_response.text[:1000])

    if new_response.status_code == 200:
        print()
        print("=" * 60)
        print("SUCCESS: NEW API KEY IS ACTIVE")
        print("=" * 60)
    else:
        print()
        print("=" * 60)
        print("ERROR: NEW API KEY WAS NOT ACCEPTED")
        print("=" * 60)


print()
print("=" * 60)
print("ATTACK SIMULATION COMPLETE")
print("=" * 60)