"""
The SecurityDecision contract.

This is THE data contract for EliteCore. Member 1 (Risk Engine) is expected to
eventually emit objects shaped exactly like `SecurityDecision` below; every
other member's stats feed the sub-fields of `evidence`. Until then, mock_data.py
and mock_stream.py generate objects in this exact shape so the dashboard never
has to change when real data arrives -- only the provider swaps.
"""

from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "SUSPICIOUS", "BLOCK"]


class ThreatIntelEvidence(BaseModel):
    matched: bool
    confidence: float
    category: str


class DGAEvidence(BaseModel):
    probability: float
    classification: str  # "DGA" | "NORMAL"


class TunnelingEvidence(BaseModel):
    rate: float
    detected: bool


class Evidence(BaseModel):
    threat_intel: ThreatIntelEvidence
    dga: DGAEvidence
    tunneling: TunnelingEvidence


class SecurityDecision(BaseModel):
    id: str
    timestamp: datetime
    domain: str
    client_ip: str
    query_type: str
    risk_score: int = Field(ge=0, le=100)
    decision: Decision
    evidence: Evidence
    rationale: str

    class Config:
        from_attributes = True


class DNSQuerySummary(BaseModel):
    id: str
    timestamp: datetime
    domain: str
    client_ip: str
    risk_score: int
    decision: Decision

    class Config:
        from_attributes = True


class PaginatedDNSQueries(BaseModel):
    items: List[DNSQuerySummary]
    page: int
    limit: int
    total: int


class TopBlockedDomain(BaseModel):
    domain: str
    count: int
    avg_risk: float


class TopBlockedResponse(BaseModel):
    items: List[TopBlockedDomain]


class TrendPoint(BaseModel):
    bucket: str
    avg_risk: float
    allowed: int
    suspicious: int
    blocked: int


class TrendResponse(BaseModel):
    granularity: str
    points: List[TrendPoint]


class MetricsSummary(BaseModel):
    total_queries: int
    allowed: int
    suspicious: int
    blocked: int
    threats: int
    average_risk_score: float
    cache_hit_rate: float
    system_status: str


class IntelStats(BaseModel):
    total_iocs: int
    active_iocs: int
    matches_today: int
    categories: dict


class MLStats(BaseModel):
    model: str
    accuracy: float
    total_predictions: int
    dga_detected: int
    normal_domains: int


class PassiveUploadResult(BaseModel):
    filename: str
    status: str
    total_packets: int
    dns_queries: int
    malicious_domains: int
    suspicious_domains: int
    dga_detected: int
    tunneling_detected: int
    blocked: int


def decision_to_evidence(q) -> "SecurityDecision":
    """Build a full SecurityDecision (with nested evidence) from a DNSQuery ORM row."""
    return SecurityDecision(
        id=q.id,
        timestamp=q.timestamp,
        domain=q.domain,
        client_ip=q.client_ip,
        query_type=q.query_type,
        risk_score=q.risk_score,
        decision=q.decision,
        evidence=Evidence(
            threat_intel=ThreatIntelEvidence(
                matched=q.threat_intel_matched,
                confidence=q.threat_intel_confidence,
                category=q.threat_category,
            ),
            dga=DGAEvidence(
                probability=q.dga_probability,
                classification=q.dga_classification,
            ),
            tunneling=TunnelingEvidence(
                rate=q.tunneling_rate,
                detected=q.tunneling_detected,
            ),
        ),
        rationale=q.rationale,
    )
