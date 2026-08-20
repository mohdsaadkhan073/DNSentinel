from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from schemas import MLStats
from services.evidence_service import get_ml_stats

router = APIRouter(prefix="/api/v1/ml", tags=["ml"])


@router.get("/stats", response_model=MLStats)
def stats(db: Session = Depends(get_db)):
    return get_ml_stats(db)
