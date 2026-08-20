"""
Shared Pydantic Schemas for DNSentinel
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SUSPICIOUS = "SUSPICIOUS"

class MLDgaResult(BaseModel):
    """ML/DGA Detection Result"""
    domain: str
    dga_probability: float = Field(ge=0.0, le=1.0)
    is_dga: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    inference_latency_ms: float
    model_version: str = "dga_rf_v1"
    features: Optional[List[float]] = None
    feature_names: Optional[List[str]] = None
    timestamp: datetime = Field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "dga_probability": round(self.dga_probability, 4),
            "is_dga": self.is_dga,
            "confidence_score": round(self.confidence_score, 4),
            "inference_latency_ms": round(self.inference_latency_ms, 2),
            "model_version": self.model_version,
            "timestamp": self.timestamp.isoformat()
        }

class DNSQuery(BaseModel):
    """DNS Query Model"""
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    source_ip: str
    domain: str
    query_type: str = "A"
    protocol: str = "UDP"
    response_code: Optional[int] = None
    latency: Optional[float] = None
    cache_hit: bool = False
    decision: Decision = Decision.ALLOW
    risk_score: float = 0.0
    ml_result: Optional[MLDgaResult] = None

class SecurityEvent(BaseModel):
    """Security Event Model"""
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    source_ip: str
    domain: str
    event_type: str  # "DGA", "TUNNEL", "THREAT_INTEL", "BEHAVIORAL"
    risk_score: float
    severity: RiskLevel
    reason: str
    decision: Decision
    evidence: Dict[str, Any] = Field(default_factory=dict)