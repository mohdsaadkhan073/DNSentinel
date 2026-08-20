import asyncio
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from config import CORS_ORIGINS, MOCK_EVENT_COUNT, MOCK_MODE
from database import init_db, SessionLocal
from mock_data import generate_mock_events
from mock_stream import run_mock_stream, save_event
from models import DNSQuery
from websocket import manager

from routes import metrics, dns, intel, ml, passive, ingest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("elitecore.main")

app = FastAPI(title="EliteCore DNS Security API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(metrics.router)
app.include_router(dns.router)
app.include_router(intel.router)
app.include_router(ml.router)
app.include_router(passive.router)
app.include_router(ingest.router)


def _seed_mock_data():
    db: Session = SessionLocal()
    try:
        existing = db.query(DNSQuery).count()
        if existing == 0:
            logger.info("Seeding %d mock DNS events", MOCK_EVENT_COUNT)
            for event in generate_mock_events(MOCK_EVENT_COUNT):
                save_event(db, event)
    finally:
        db.close()


@app.on_event("startup")
async def on_startup():
    init_db()
    if MOCK_MODE:
        _seed_mock_data()
        asyncio.create_task(run_mock_stream())
        logger.info("MOCK_MODE=on -- seeding mock data and running the mock stream")
    else:
        logger.info("MOCK_MODE=off -- waiting for real data on POST /api/v1/ingest/decision")


@app.get("/")
def root():
    return {"service": "EliteCore DNS Security API", "status": "ONLINE"}


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


@app.websocket("/ws/telemetry")
async def telemetry_socket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Client isn't expected to send anything; keep the connection alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
