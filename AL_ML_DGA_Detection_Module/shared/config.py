"""
Global Configuration for DNSentinel
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
MODEL_DIR = BASE_DIR / "ml" / "models"
DATA_DIR = BASE_DIR / "data"

# ML Configuration
ML_CONFIG = {
    "model_version": "dga_rf_v1",
    "model_path": str(MODEL_DIR / "dga_rf_v1.pkl"),
    "n_estimators": 100,
    "max_depth": 20,
    "min_samples_split": 5,
    "random_state": 42,
    "dga_threshold": 0.70,  # DGA probability threshold
    "inference_timeout_ms": 8,  # Max inference time
    "feature_count": 12,
}

# Feature names (for explainability)
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

# Risk weights (for integration with Risk Engine)
RISK_WEIGHTS = {
    "ml_weight": 0.40,
    "intel_weight": 1.0,
    "tunnel_weight": 0.35,
    "behavior_weight": 0.25,
}

# Thresholds
THRESHOLDS = {
    "block_threshold": 70.0,
    "suspicious_threshold": 40.0,
    "dga_threshold": 0.70,
}

# Dataset configuration
DATASET_CONFIG = {
    "tranco_url": "https://tranco-list.eu/top-1m.csv.zip",
    "dga_url": "https://data.netlab.360.com/dga/dga-data/",  # Netlab DGA dataset
    "clean_domains_count": 10000,
    "dga_domains_count": 10000,
    "test_split_ratio": 0.2,
}