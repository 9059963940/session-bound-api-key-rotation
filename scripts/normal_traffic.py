import sys
import time
import requests


BASE_URL = "http://127.0.0.1:8000"
API_KEY = sys.argv[1] if len(sys.argv) > 1 else ""


if not API_KEY:
    print("ERROR: API key not provided.")
    print()
    print("Usage:")
    print("python scripts/normal_traffic.py YOUR_API_KEY")
    sys.exit(1)


headers = {
    "X-API-Key": API_KEY
}


TOTAL_REQUESTS = 30
DELAY_SECONDS = 0.25


print("=" * 60)
print("SESSION-BOUND API KEY SECURITY")
print("NORMAL BASELINE TRAFFIC")
print("=" * 60)

print(f"Target: {BASE_URL}/api/secure-data")
print(f"Requests: {TOTAL_REQUESTS}")
print(f"Delay: {DELAY_SECONDS} seconds")
print()

successful = 0
failed = 0


for i in range(1, TOTAL_REQUESTS + 1):

    try:
        response = requests.get(
            f"{BASE_URL}/api/secure-data",
            headers=headers,
            timeout=10
        )

        try:
            data = response.json()
        except Exception:
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

        if response.status_code == 200:
            successful += 1
        else:
            failed += 1

    except requests.RequestException as exc:
        print(
            f"{i:02d} | REQUEST ERROR | {exc}"
        )
        failed += 1

    time.sleep(DELAY_SECONDS)


print()
print("=" * 60)
print("NORMAL TRAFFIC COMPLETE")
print("=" * 60)
print(f"Successful requests: {successful}")
print(f"Failed requests:     {failed}")
print()