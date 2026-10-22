
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = Path(
    os.environ.get("DB_PATH", str(DATA_DIR / "security.db"))
).expanduser().resolve()

BASELINE_REQUESTS = 30
HIGH_RISK_THRESHOLD = 0.65
ROTATION_COOLDOWN_SECONDS = 20
SERVICE_NAME = "authorized-service"

# Admin authentication token must be supplied through the environment.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

if not ADMIN_TOKEN:
    raise RuntimeError(
        "ADMIN_TOKEN is not set. Configure it before starting the application."
    )
