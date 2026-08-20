from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from schemas import PaginatedDNSQueries, SecurityDecision, TopBlockedResponse
from schemas import decision_to_evidence
from services.dns_service import list_queries, get_query, get_top_blocked

router = APIRouter(prefix="/api/v1/dns", tags=["dns"])


@router.get("/queries", response_model=PaginatedDNSQueries)
def queries(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    decision: Optional[str] = Query(None, pattern="^(ALLOW|SUSPICIOUS|BLOCK)$"),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    items, total = list_queries(db, page, limit, decision, search)
    return {"items": items, "page": page, "limit": limit, "total": total}


@router.get("/queries/{query_id}", response_model=SecurityDecision)
def query_detail(query_id: str, db: Session = Depends(get_db)):
    row = get_query(db, query_id)
    if not row:
        raise HTTPException(status_code=404, detail="Query not found")
    return decision_to_evidence(row)


@router.get("/top-blocked", response_model=TopBlockedResponse)
def top_blocked(limit: int = Query(5, ge=1, le=20), db: Session = Depends(get_db)):
    return {"items": get_top_blocked(db, limit)}
