from typing import Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from models import DNSQuery


def list_queries(db: Session, page: int, limit: int, decision: Optional[str], search: Optional[str]):
    query = db.query(DNSQuery)
    if decision:
        query = query.filter(DNSQuery.decision == decision.upper())
    if search:
        query = query.filter(DNSQuery.domain.ilike(f"%{search}%"))

    total = query.count()
    items = (
        query.order_by(DNSQuery.timestamp.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )
    return items, total


def get_query(db: Session, query_id: str) -> Optional[DNSQuery]:
    return db.query(DNSQuery).filter(DNSQuery.id == query_id).first()


def get_top_blocked(db: Session, limit: int = 5):
    rows = (
        db.query(
            DNSQuery.domain,
            func.count(DNSQuery.id).label("count"),
            func.avg(DNSQuery.risk_score).label("avg_risk"),
        )
        .filter(DNSQuery.decision == "BLOCK")
        .group_by(DNSQuery.domain)
        .order_by(func.count(DNSQuery.id).desc())
        .limit(limit)
        .all()
    )
    return [
        {"domain": domain, "count": count, "avg_risk": round(float(avg_risk), 1)}
        for domain, count, avg_risk in rows
    ]
