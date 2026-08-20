from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from schemas import MetricsSummary, TrendResponse
from services.metrics_service import get_summary, get_trend

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])


@router.get("/summary", response_model=MetricsSummary)
def summary(db: Session = Depends(get_db)):
    return get_summary(db)


@router.get("/trend", response_model=TrendResponse)
def trend(granularity: str = Query("hour", pattern="^(hour|day)$"), db: Session = Depends(get_db)):
    return get_trend(db, granularity)
