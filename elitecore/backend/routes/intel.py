from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from schemas import IntelStats
from services.evidence_service import get_intel_stats

router = APIRouter(prefix="/api/v1/intel", tags=["intel"])


@router.get("/stats", response_model=IntelStats)
def stats(db: Session = Depends(get_db)):
    return get_intel_stats(db)
