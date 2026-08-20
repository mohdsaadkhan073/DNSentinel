import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "elitecore.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

os.makedirs(UPLOAD_DIR, exist_ok=True)

CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Set MOCK_MODE=off once a teammate's module is POSTing real decisions to
# /api/v1/ingest/decision, so seeded mock rows and the mock stream don't mix
# with real data in the same demo.
MOCK_MODE = os.environ.get("MOCK_MODE", "on").strip().lower() != "off"

MOCK_EVENT_COUNT = 90
MOCK_STREAM_MIN_INTERVAL = 1.0
MOCK_STREAM_MAX_INTERVAL = 3.0

RISK_LOW_MAX = 29
RISK_MEDIUM_MAX = 59
RISK_HIGH_MAX = 79
