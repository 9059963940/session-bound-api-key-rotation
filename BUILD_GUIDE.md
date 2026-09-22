# BUILD GUIDE — macOS / Apple Silicon

This project is a local prototype of the system described in the supplied Review-1 document.

## 1. Install Python
Use Python 3.11, 3.12, or 3.13 for the smoothest scikit-learn setup.

Check:
python3 --version

## 2. Put the project on Desktop
Download and unzip the supplied ZIP, then in Terminal:

cd ~/Desktop/session_bound_api_key_rotation

## 3. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

## 4. Start the gateway
Terminal 1:

cd ~/Desktop/session_bound_api_key_rotation
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

Open:
http://127.0.0.1:8000/docs

## 5. Issue a key
Terminal 2:

cd ~/Desktop/session_bound_api_key_rotation
source .venv/bin/activate
python scripts/issue_key.py

Copy the API key.

## 6. Establish normal behavior
Open scripts/normal_traffic.py and replace:
PASTE_YOUR_API_KEY_HERE

Run:
python scripts/normal_traffic.py

The prototype learns from at least 30 requests.

## 7. Start dashboard
Terminal 3:

cd ~/Desktop/session_bound_api_key_rotation
source .venv/bin/activate
streamlit run dashboard/app.py

Open http://localhost:8501 if the browser does not open automatically.

## 8. Simulate suspicious behavior
Put the ORIGINAL key into scripts/simulate_attack.py.

Run:
python scripts/simulate_attack.py

The User-Agent changes and traffic becomes a rapid burst. The anomaly detector calculates a risk score. When the configured threshold is crossed, the old key is revoked and a new session-bound key is created.

## 9. Verify the rotation
Open:
http://127.0.0.1:8000/admin/keys
http://127.0.0.1:8000/admin/rotations
http://127.0.0.1:8000/admin/requests

Refresh the Streamlit dashboard.

## 10. Reset
Stop the gateway/dashboard with Ctrl+C, then:

source .venv/bin/activate
python scripts/reset_project.py

## 11. Review demonstration
Recommended demonstration:
1. Explain the architecture.
2. Issue Key A.
3. Send normal requests.
4. Explain baseline learning.
5. Show low-risk normal traffic.
6. Simulate attacker behavior.
7. Show anomaly and risk score.
8. Show Key A becoming revoked.
9. Show Key B/session ID being generated.
10. Show the audit log.
11. Show the monitoring dashboard.
12. Discuss exposure-window reduction conceptually.

## Mapping to the Review-1 requirements
Usage profiling -> request logging + app/features.py
Anomaly detection -> app/anomaly.py using Isolation Forest
Risk score -> app/anomaly.py
Key rotation -> app/rotation.py
Key vault -> app/key_vault.py
API gateway -> app/main.py
Audit trail -> app/database.py
Monitoring dashboard -> dashboard/app.py

## Important limitation
The review document explicitly describes a simulated multi-service testbed and a lightweight prototype. This implementation follows that scope. It is not a production KMS/HSM deployment and should not be presented as one.
