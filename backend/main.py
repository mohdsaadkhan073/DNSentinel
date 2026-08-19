import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from shared.schemas import MetricsSummary, DNSQuery, ActionDecision
from shared.config import FASTAPI_HOST, FASTAPI_PORT
from backend.database import DatabaseManager
from backend.websocket import WebSocketManager
from core.orchestrator import Orchestrator
from resolver.dns_cache import DNSCache
from threat_intel.ioc_store import IOCStore
from ml.dga_classifier import DGAClassifier
from passive.tunnel_detector import TunnelDetector
from passive.pcap_parser import PCAPParser
from passive.batch_analyzer import BatchAnalyzer

app = FastAPI(
    title="EliteCore DNS Threat Detection Telemetry API",
    version="2.0.0",
    description="FastAPI REST & WebSocket Backend for SIH1524"
)

# CORS configuration for React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate Core System Components
dns_cache = DNSCache()
ioc_store = IOCStore()
dga_classifier = DGAClassifier()
tunnel_detector = TunnelDetector()
orchestrator = Orchestrator(
    ioc_store=ioc_store,
    dga_classifier=dga_classifier,
    tunnel_detector=tunnel_detector,
    dns_cache=dns_cache
)

db_manager = DatabaseManager()
ws_manager = WebSocketManager()
batch_analyzer = BatchAnalyzer(orchestrator=orchestrator)

@app.on_event("startup")
async def startup_event():
    await db_manager.init_db()
    print("[Backend] EliteCore FastAPI Telemetry Server initialized successfully.")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "EliteCore SIH1524 DNS Security Platform",
        "version": "v2.0 Master Spec"
    }

@app.get("/api/v1/metrics/summary")
def get_metrics_summary():
    return MetricsSummary(
        total_queries=1240,
        blocked_queries=182,
        suspicious_queries=45,
        allowed_queries=1013,
        cache_hits=680,
        avg_latency_ms=12.4,
        dga_detected_count=78,
        tunnels_detected_count=23
    )

@app.get("/api/v1/dns/queries")
async def get_recent_queries(limit: int = 50):
    return await db_manager.get_recent_queries(limit=limit)

@app.get("/api/v1/intel/stats")
def get_intel_stats():
    return {
        "total_iocs_loaded": ioc_store.total_iocs(),
        "stix_version": "2.1",
        "taxii_version": "2.1",
        "active_feeds": ["MITRE ATT&CK C2", "AlienVault OTX", "Abuse.ch Feeds"],
        "lookup_latency_ms": "< 2.0ms"
    }

@app.post("/api/v1/dns/evaluate")
async def evaluate_dns_query(domain: str, client_ip: str = "192.168.1.100", qtype: str = "A"):
    query = DNSQuery(
        query_id="eval-01",
        domain=domain,
        client_ip=client_ip,
        qtype=qtype
    )
    decision = orchestrator.process_query(query)
    await db_manager.log_decision(decision)
    await ws_manager.broadcast(decision.model_dump(mode="json"))
    return decision

@app.post("/api/v1/passive/upload-pcap")
async def upload_pcap_file(file: UploadFile = File(...)):
    contents = await file.read()
    parsed_queries = PCAPParser.parse_pcap(contents)
    report = batch_analyzer.analyze_batch(parsed_queries)
    return {
        "filename": file.filename,
        "total_queries_analyzed": report["total_queries"],
        "blocked": report["blocked_count"],
        "suspicious": report["suspicious_count"],
        "allowed": report["allowed_count"],
        "sample_decisions": report["decisions"][:10]
    }

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=FASTAPI_HOST, port=FASTAPI_PORT, reload=True)
