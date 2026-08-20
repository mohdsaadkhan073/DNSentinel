import os

# Graceful env loader with fallback to eliminate IDE import squigglies
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except (ImportError, Exception):
    # Built-in zero-dependency fallback .env loader
    if os.path.exists(".env"):
        try:
            with open(".env", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())
        except Exception:
            pass

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
RISK_THRESHOLD_SUSPICIOUS = float(os.getenv("RISK_THRESHOLD_SUSPICIOUS", "40.0"))

# Risk Formula Weights
WEIGHT_THREAT_INTEL = 1.0
WEIGHT_ML_DGA = 0.40
WEIGHT_TUNNEL = 0.35
WEIGHT_BEHAVIOR = 0.25

# Detection Performance SLAs
DETECTION_TIMEOUT_SEC = float(os.getenv("DETECTION_TIMEOUT_SEC", "0.025"))

# Database & File Paths
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "dnsentinel_telemetry.db")
ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "ml/dga_rf_v1.pkl")
