import pytest
import asyncio
import time
from shared.schemas import (
    DNSQuery,
    ProtocolType,
    ActionDecision,
    ThreatIntelResult,
    MLDgaResult,
    TunnelResult,
    SecurityDecision
)
from shared.config import (
    RISK_THRESHOLD_BLOCK,
    RISK_THRESHOLD_SUSPICIOUS,
    WEIGHT_THREAT_INTEL,
    WEIGHT_ML_DGA,
    WEIGHT_TUNNEL,
    WEIGHT_BEHAVIOR
)
from core.risk_engine import RiskEngine
from core.orchestrator import Orchestrator

def test_risk_engine_clean_domain():
    intel = ThreatIntelResult(matched=False, intel_score=0.0)
    ml = MLDgaResult(is_dga=False, dga_probability=0.05)
    tunnel = TunnelResult(is_tunnel=False, tunnel_score=0.0)

    score, decision, rationale = RiskEngine.calculate_risk(intel, ml, tunnel)
    assert score == 2.0  # 0.40 * 5 = 2.0
    assert decision == ActionDecision.ALLOW
    assert "Allowed" in rationale

def test_risk_engine_suspicious_domain():
    intel = ThreatIntelResult(matched=False, intel_score=0.0)
    ml = MLDgaResult(is_dga=True, dga_probability=0.85)  # 0.40 * 85 = 34
    tunnel = TunnelResult(is_tunnel=True, tunnel_score=50.0)  # 0.35 * 50 = 17.5

    # Total = 34 + 17.5 = 51.5 -> SUSPICIOUS (>=40, <70)
    score, decision, rationale = RiskEngine.calculate_risk(intel, ml, tunnel)
    assert score == 51.5
    assert decision == ActionDecision.SUSPICIOUS
    assert "Suspicious" in rationale

def test_risk_engine_blocked_high_score():
    intel = ThreatIntelResult(matched=False, intel_score=0.0)
    ml = MLDgaResult(is_dga=True, dga_probability=0.95)  # 0.40 * 95 = 38
    tunnel = TunnelResult(is_tunnel=True, tunnel_score=90.0)  # 0.35 * 90 = 31.5
    behavior = 60.0  # 0.25 * 60 = 15

    # Total = 38 + 31.5 + 15 = 84.5 -> BLOCK (>=70)
    score, decision, rationale = RiskEngine.calculate_risk(intel, ml, tunnel, behavior_score=behavior)
    assert score == 84.5
    assert decision == ActionDecision.BLOCK
    assert "Blocked" in rationale

def test_risk_engine_threat_intel_direct_match_override():
    intel = ThreatIntelResult(matched=True, threat_category="Malicious C2", intel_score=100.0)
    ml = MLDgaResult(is_dga=False, dga_probability=0.0)
    tunnel = TunnelResult(is_tunnel=False, tunnel_score=0.0)

    score, decision, rationale = RiskEngine.calculate_risk(intel, ml, tunnel)
    assert score == 100.0
    assert decision == ActionDecision.BLOCK
    assert "Direct Threat Intel match" in rationale

def test_orchestrator_sync_evaluation():
    query = DNSQuery(
        query_id="test-sync-1",
        domain="example.com",
        client_ip="192.168.1.50",
        protocol=ProtocolType.UDP
    )
    orchestrator = Orchestrator()
    decision = orchestrator.process_query(query)

    assert isinstance(decision, SecurityDecision)
    assert decision.action == ActionDecision.ALLOW
    assert decision.resolved_ip == "8.8.8.8"
    assert decision.latency_ms >= 0.0

def test_orchestrator_async_parallel_fanout():
    async def run():
        query = DNSQuery(
            query_id="test-async-1",
            domain="malicious-dga-test.biz",
            client_ip="192.168.1.51",
            protocol=ProtocolType.DOH
        )

        class MockML:
            def predict(self, domain):
                return MLDgaResult(is_dga=True, dga_probability=0.90)

        class MockTunnel:
            def analyze(self, query):
                return TunnelResult(is_tunnel=True, tunnel_score=80.0)

        orchestrator = Orchestrator(dga_classifier=MockML(), tunnel_detector=MockTunnel())
        decision = await orchestrator.process_query_async(query)

        assert isinstance(decision, SecurityDecision)
        # Score = 0.40*90 + 0.35*80 = 36 + 28 = 64.0 -> SUSPICIOUS
        assert decision.composite_risk_score == 64.0
        assert decision.action == ActionDecision.SUSPICIOUS

    asyncio.run(run())

def test_orchestrator_async_timeout_protection():
    async def run():
        query = DNSQuery(
            query_id="test-timeout-1",
            domain="slow-module.com",
            client_ip="10.0.0.1",
            protocol=ProtocolType.DTLS
        )

        class SlowThreatIntel:
            async def lookup(self, domain):
                await asyncio.sleep(0.5)  # Intentionally exceeds 25ms timeout
                return ThreatIntelResult(matched=True, intel_score=100.0)

        orchestrator = Orchestrator(ioc_store=SlowThreatIntel())
        start = time.perf_counter()
        decision = await orchestrator.process_query_async(query, timeout_sec=0.025)
        duration_ms = (time.perf_counter() - start) * 1000.0

        # Must complete fast and fall back gracefully
        assert duration_ms < 100.0
        assert decision.action == ActionDecision.ALLOW

    asyncio.run(run())

