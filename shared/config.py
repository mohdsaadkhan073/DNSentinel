import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
MODEL_DIR = BASE_DIR / "ml" / "models"
DATA_DIR = BASE_DIR / "data"

# ML Configuration
ML_CONFIG = {
    "model_version": "dga_rf_v1",
    "model_path": os.getenv("ML_MODEL_PATH", str(MODEL_DIR / "dga_rf_v1.pkl")),
    "n_estimators": 100,
    "max_depth": 20,
    "min_samples_split": 5,
    "random_state": 42,
    "dga_threshold": 0.70,
    "inference_timeout_ms": 8,
    "feature_count": 12,
}

FEATURE_NAMES = [
    "shannon_entropy",
    "domain_length",
    "vowel_ratio",
    "digit_ratio",
    "hyphen_ratio",
    "max_consecutive_consonants",
    "max_consecutive_digits",
    "hex_ratio",
    "bigram_score",
    "trigram_score",
    "subdomain_depth",
    "unique_char_ratio"
]

# Network Listener Defaults
FASTAPI_HOST = os.getenv("FASTAPI_HOST", "0.0.0.0")
FASTAPI_PORT = int(os.getenv("FASTAPI_PORT", "8000"))
DNS_UDP_PORT = int(os.getenv("DNS_UDP_PORT", "53"))
DNS_DOH_PORT = int(os.getenv("DNS_DOH_PORT", "8443"))
DNS_DTLS_PORT = int(os.getenv("DNS_DTLS_PORT", "853"))

# Upstream Resolver
UPSTREAM_DNS_PRIMARY = os.getenv("UPSTREAM_DNS_PRIMARY", "8.8.8.8")
UPSTREAM_DNS_SECONDARY = os.getenv("UPSTREAM_DNS_SECONDARY", "1.1.1.1")

# Security Decision Boundaries
RISK_THRESHOLD_BLOCK = float(os.getenv("RISK_THRESHOLD_BLOCK", "70.0"))
RISK_THRESHOLD_SUSPICIOUS = float(os.getenv("RISK_THRESHOLD_SUSPICIOUS", "35.0"))

# Risk Formula Weights
WEIGHT_THREAT_INTEL = 1.0
WEIGHT_ML_DGA = 0.40
WEIGHT_TUNNEL = 0.35
WEIGHT_BEHAVIOR = 0.25

# Detection Performance SLAs
DETECTION_TIMEOUT_SEC = float(os.getenv("DETECTION_TIMEOUT_SEC", "0.025"))

# Database & File Paths
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "dnsentinel_telemetry.db")
ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "ml/models/dga_rf_v1.pkl")
