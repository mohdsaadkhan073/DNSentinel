"""Background task that emits a new mock DNS event every 1-3 seconds and
broadcasts it over the WebSocket, while also persisting it to SQLite so
REST clients (and reconnecting WebSocket clients) see a consistent history.

save_event / persist_and_broadcast are shared with routes/ingest.py, which is
the real integration point once Members 1-5 have live SecurityDecision data.
"""

import asyncio
import logging
import random
from datetime import datetime

from config import MOCK_STREAM_MIN_INTERVAL, MOCK_STREAM_MAX_INTERVAL
from database import SessionLocal
from mock_data import generate_event
from models import DNSQuery
from schemas import SecurityDecision
from websocket import manager

logger = logging.getLogger("elitecore.mock_stream")


def save_event(db, event: dict) -> DNSQuery:
    """Persist a SecurityDecision-shaped dict. Uses merge() so re-sending the
    same id (e.g. a retried POST from an integration) upserts instead of
    raising a primary-key conflict."""
    row = DNSQuery(
        id=event["id"],
        timestamp=datetime.fromisoformat(event["timestamp"]),
        domain=event["domain"],
        client_ip=event["client_ip"],
        query_type=event["query_type"],
        risk_score=event["risk_score"],
        decision=event["decision"],
        threat_intel_matched=event["evidence"]["threat_intel"]["matched"],
        threat_intel_confidence=event["evidence"]["threat_intel"]["confidence"],
        threat_category=event["evidence"]["threat_intel"]["category"],
        dga_probability=event["evidence"]["dga"]["probability"],
        dga_classification=event["evidence"]["dga"]["classification"],
        tunneling_rate=event["evidence"]["tunneling"]["rate"],
        tunneling_detected=event["evidence"]["tunneling"]["detected"],
        rationale=event["rationale"],
    )
    row = db.merge(row)
    db.commit()
    return row


async def persist_and_broadcast(decision: SecurityDecision) -> dict:
    """The real-integration entry point: save a real SecurityDecision to the
    DB and push it to every connected dashboard exactly like a mock event."""
    event = decision.model_dump(mode="json")
    db = SessionLocal()
    try:
        save_event(db, event)
    finally:
        db.close()
    await manager.broadcast(event)
    return event


async def run_mock_stream():
    logger.info("Mock telemetry stream started")
    while True:
        await asyncio.sleep(random.uniform(MOCK_STREAM_MIN_INTERVAL, MOCK_STREAM_MAX_INTERVAL))
        event = generate_event()
        db = SessionLocal()
        try:
            save_event(db, event)
        finally:
            db.close()
        await manager.broadcast(event)
