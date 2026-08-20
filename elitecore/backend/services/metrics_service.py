from sqlalchemy import func, case
from sqlalchemy.orm import Session

from models import DNSQuery


def get_summary(db: Session) -> dict:
    total = db.query(func.count(DNSQuery.id)).scalar() or 0
    allowed = db.query(func.count(DNSQuery.id)).filter(DNSQuery.decision == "ALLOW").scalar() or 0
    suspicious = db.query(func.count(DNSQuery.id)).filter(DNSQuery.decision == "SUSPICIOUS").scalar() or 0
    blocked = db.query(func.count(DNSQuery.id)).filter(DNSQuery.decision == "BLOCK").scalar() or 0
    threats = db.query(func.count(DNSQuery.id)).filter(DNSQuery.threat_intel_matched.is_(True)).scalar() or 0
    avg_risk = db.query(func.avg(DNSQuery.risk_score)).scalar() or 0.0

    return {
        "total_queries": total,
        "allowed": allowed,
        "suspicious": suspicious,
        "blocked": blocked,
        "threats": threats,
        "average_risk_score": round(float(avg_risk), 1),
        "cache_hit_rate": 87.4,  # placeholder until Member 2 (resolver) provides real metric
        "system_status": "ONLINE",
    }


def get_trend(db: Session, granularity: str = "hour") -> dict:
    """Bucket real logged decisions by hour or day. Buckets with no data are
    simply absent -- this reflects actual history, not padded/fabricated."""
    fmt = "%Y-%m-%dT%H:00" if granularity == "hour" else "%Y-%m-%d"
    bucket_expr = func.strftime(fmt, DNSQuery.timestamp)

    rows = (
        db.query(
            bucket_expr.label("bucket"),
            func.avg(DNSQuery.risk_score).label("avg_risk"),
            func.sum(case((DNSQuery.decision == "ALLOW", 1), else_=0)).label("allowed"),
            func.sum(case((DNSQuery.decision == "SUSPICIOUS", 1), else_=0)).label("suspicious"),
            func.sum(case((DNSQuery.decision == "BLOCK", 1), else_=0)).label("blocked"),
        )
        .group_by(bucket_expr)
        .order_by(bucket_expr)
        .all()
    )

    points = [
        {
            "bucket": bucket,
            "avg_risk": round(float(avg_risk), 1),
            "allowed": allowed,
            "suspicious": suspicious,
            "blocked": blocked,
        }
        for bucket, avg_risk, allowed, suspicious, blocked in rows
    ]
    return {"granularity": granularity, "points": points}
