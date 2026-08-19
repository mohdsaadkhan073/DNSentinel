from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class ProtocolType(str, Enum):
    UDP = "UDP"
    DOH = "DoH"
    DTLS = "DTLS"
    PASSIVE = "PASSIVE"

class ActionDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SUSPICIOUS = "SUSPICIOUS"

class DNSQuery(BaseModel):
    query_id: str
    domain: str
    client_ip: str
    protocol: ProtocolType = ProtocolType.UDP
    qtype: str = "A"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ThreatIntelResult(BaseModel):
    matched: bool = False
    threat_category: Optional[str] = None
    intel_score: float = 0.0  # 0 to 100
    source_feed: Optional[str] = None
    details: Optional[str] = None

class MLDgaResult(BaseModel):
    is_dga: bool = False
    dga_probability: float = 0.0  # 0.0 to 1.0
    model_version: str = "v1.0"
    features: Optional[Dict[str, float]] = None

class TunnelResult(BaseModel):
    is_tunnel: bool = False
    tunnel_score: float = 0.0  # 0 to 100
    entropy: float = 0.0
    query_length: int = 0
    reason: Optional[str] = None

class SecurityDecision(BaseModel):
    decision_id: str
    query: DNSQuery
    action: ActionDecision
    composite_risk_score: float  # 0 to 100
    intel_result: ThreatIntelResult
    ml_result: MLDgaResult
    tunnel_result: TunnelResult
    behavior_score: float = 0.0
    latency_ms: float
    cache_hit: bool = False
    resolved_ip: Optional[str] = None
    rationale: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class MetricsSummary(BaseModel):
    total_queries: int = 0
    blocked_queries: int = 0
    suspicious_queries: int = 0
    allowed_queries: int = 0
    cache_hits: int = 0
    avg_latency_ms: float = 0.0
    dga_detected_count: int = 0
    tunnels_detected_count: int = 0
