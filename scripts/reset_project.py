from app.config import DB_PATH

if DB_PATH.exists():
    DB_PATH.unlink()
    print("Database reset.")
else:
    print("Database does not exist yet.")
