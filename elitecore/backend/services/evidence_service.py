"""Threat-intel and ML/DGA aggregate stats.

These are mocked today (Member 3 / Member 4 own the real numbers) but are
computed partly from real DB contents so they move in step with the live
mock stream instead of staying static.
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from models import DNSQuery


def get_intel_stats(db: Session) -> dict:
    matches_today = db.query(func.count(DNSQuery.id)).filter(DNSQuery.threat_intel_matched.is_(True)).scalar() or 0

    categories = {"malware": 0, "phishing": 0, "botnet": 0, "ransomware": 0, "other": 0}
    rows = (
        db.query(DNSQuery.threat_category, func.count(DNSQuery.id))
        .filter(DNSQuery.threat_intel_matched.is_(True))
        .group_by(DNSQuery.threat_category)
        .all()
    )
    for category, count in rows:
        if category in categories:
            categories[category] = count

    return {
        "total_iocs": 18234,
        "active_iocs": 16482,
        "matches_today": matches_today,
        "categories": categories,
    }


def get_ml_stats(db: Session) -> dict:
    total = db.query(func.count(DNSQuery.id)).scalar() or 0
    dga_detected = db.query(func.count(DNSQuery.id)).filter(DNSQuery.dga_classification == "DGA").scalar() or 0

    return {
        "model": "DGA Classifier",
        "accuracy": 0.94,
        "total_predictions": total,
        "dga_detected": dga_detected,
        "normal_domains": max(total - dga_detected, 0),
    }
