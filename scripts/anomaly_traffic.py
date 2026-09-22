import sys
import time
import requests


BASE_URL = "http://127.0.0.1:8000"


def run_anomaly_test(api_key):
    url = f"{BASE_URL}/api/secure-data"

    headers = {
        "X-API-Key": api_key,
        "User-Agent": "ANOMALOUS-CLIENT/1.0"
    }

    print("=" * 60)
    print("SESSION-BOUND API KEY SECURITY")
    print("ANOMALOUS TRAFFIC TEST")
    print("=" * 60)

    print(f"Target: {url}")
    print("Traffic type: unusual client fingerprint")
    print("Requests: 10")
    print()

    for i in range(1, 11):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=5
            )

            try:
                data = response.json()
            except ValueError:
                data = {}

            security = data.get("security", {})

            risk = security.get("risk_score", "N/A")
            anomaly = security.get("anomaly_score", "N/A")
            reason = security.get("reason", "")

            print(
                f"{i:02d} | "
                f"HTTP {response.status_code} | "
                f"Risk={risk} | "
                f"Anomaly={anomaly} | "
                f"{reason}"
            )

            if security.get("rotated"):
                print()
                print("!!! AUTOMATIC ROTATION DETECTED !!!")

                new_key = security.get("new_api_key")

                if new_key:
                    print(f"New API key generated: {new_key}")

                print()
                print("The original API key has been revoked.")
                break

        except requests.RequestException as e:
            print(f"{i:02d} | REQUEST ERROR | {e}")

        time.sleep(0.5)

    print()
    print("=" * 60)
    print("ANOMALOUS TRAFFIC TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print()
        print("Usage:")
        print("python scripts/anomaly_traffic.py YOUR_API_KEY")
        print()
        sys.exit(1)

    api_key = sys.argv[1]

    run_anomaly_test(api_key)