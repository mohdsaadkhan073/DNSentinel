import sqlite3
import json
import asyncio
from typing import List, Dict, Any
from shared.config import SQLITE_DB_PATH
from shared.schemas import SecurityDecision

class DatabaseManager:
    """
    SQLite Query Telemetry Database Manager (Stdlib sqlite3).
    Owned by Member 6 (Dashboard Lead).
    """

    def __init__(self, db_path: str = SQLITE_DB_PATH):
        self.db_path = db_path

    async def init_db(self):
        def _sync_init():
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS query_logs (
                    decision_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    action TEXT NOT NULL,
                    composite_risk_score REAL NOT NULL,
                    intel_matched INTEGER NOT NULL,
                    is_dga INTEGER NOT NULL,
                    is_tunnel INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    cache_hit INTEGER NOT NULL,
                    rationale TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()

        await asyncio.to_thread(_sync_init)

    async def log_decision(self, decision: SecurityDecision):
        def _sync_log():
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO query_logs (
                    decision_id, domain, client_ip, protocol, action,
                    composite_risk_score, intel_matched, is_dga, is_tunnel,
                    latency_ms, cache_hit, rationale, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision.decision_id,
                decision.query.domain,
                decision.query.client_ip,
                decision.query.protocol.value,
                decision.action.value,
                decision.composite_risk_score,
                1 if decision.intel_result.matched else 0,
                1 if decision.ml_result.is_dga else 0,
                1 if decision.tunnel_result.is_tunnel else 0,
                decision.latency_ms,
                1 if decision.cache_hit else 0,
                decision.rationale,
                json.dumps(decision.model_dump(), default=str)
            ))
            conn.commit()
            conn.close()

        await asyncio.to_thread(_sync_log)

    async def get_recent_queries(self, limit: int = 50) -> List[Dict[str, Any]]:
        def _sync_get():
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT raw_json FROM query_logs ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            conn.close()
            return [json.loads(row[0]) for row in rows]

        return await asyncio.to_thread(_sync_get)

    async def get_metrics_summary(self) -> Dict[str, Any]:
        def _sync_metrics():
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    COUNT(*),
                    SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN action = 'SUSPICIOUS' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN cache_hit = 1 THEN 1 ELSE 0 END),
                    AVG(latency_ms),
                    SUM(CASE WHEN is_dga = 1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN is_tunnel = 1 THEN 1 ELSE 0 END)
                FROM query_logs
            """)
            row = cursor.fetchone()
            conn.close()
            total = row[0] or 0
            if total == 0:
                return {
                    "total_queries": 0,
                    "blocked_queries": 0,
                    "suspicious_queries": 0,
                    "allowed_queries": 0,
                    "cache_hits": 0,
                    "avg_latency_ms": 0.0,
                    "dga_detected_count": 0,
                    "tunnels_detected_count": 0
                }
            return {
                "total_queries": total,
                "blocked_queries": row[1] or 0,
                "suspicious_queries": row[2] or 0,
                "allowed_queries": row[3] or 0,
                "cache_hits": row[4] or 0,
                "avg_latency_ms": float(round(row[5] or 0.0, 2)),
                "dga_detected_count": row[6] or 0,
                "tunnels_detected_count": row[7] or 0
            }

        return await asyncio.to_thread(_sync_metrics)
