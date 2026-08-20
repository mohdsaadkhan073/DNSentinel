"""The real integration endpoint.

Members 1-5: once your module can produce a real SecurityDecision (see
schemas.py / README.md for the exact shape), POST it here as soon as you
compute it. It gets validated against the contract, saved to the same
database the REST endpoints read from, and broadcast to every connected
dashboard over the same WebSocket the mock stream uses -- so there is
nothing else to wire up on the dashboard side.

Run the backend with MOCK_MODE=off once real decisions are flowing so mock
and real data don't mix in the same demo.
"""

from fastapi import APIRouter

from mock_stream import persist_and_broadcast
from schemas import SecurityDecision

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


@router.post("/decision", response_model=SecurityDecision)
async def ingest_decision(decision: SecurityDecision):
    await persist_and_broadcast(decision)
    return decision
