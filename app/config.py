from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "security.db"

BASELINE_REQUESTS = 30
HIGH_RISK_THRESHOLD = 0.65
ROTATION_COOLDOWN_SECONDS = 20
SERVICE_NAME = "authorized-service"
