import time
import uuid
from typing import Optional
from shared.schemas import (
    DNSQuery,
    SecurityDecision,
    ActionDecision,
    ThreatIntelResult,
    MLDgaResult,
    TunnelResult
)
from core.risk_engine import RiskEngine

class Orchestrator:
    """
    Parallel orchestration engine coordinating Threat Intel, ML DGA, and Tunneling detectors.
    Owned by Member 1 (Team Lead).
    """

    def __init__(self, ioc_store=None, dga_classifier=None, tunnel_detector=None, dns_cache=None):
        self.ioc_store = ioc_store
        self.dga_classifier = dga_classifier
        self.tunnel_detector = tunnel_detector
        self.dns_cache = dns_cache

    def process_query(self, query: DNSQuery) -> SecurityDecision:
        start_time = time.perf_counter()

        # Step 1: Check DNS Cache (< 5ms)
        if self.dns_cache:
            cached_result = self.dns_cache.get(query.domain)
            if cached_result:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                cached_result.query = query
                cached_result.cache_hit = True
                cached_result.latency_ms = float(round(elapsed_ms, 2))
                return cached_result

        # Step 2: Threat Intel Lookup (Member 3)
        if self.ioc_store:
            intel_res = self.ioc_store.lookup(query.domain)
        else:
            intel_res = ThreatIntelResult(matched=False, intel_score=0.0)

        # Fast path if threat match
        if intel_res.matched:
            ml_res = MLDgaResult(is_dga=False, dga_probability=0.0)
            tunnel_res = TunnelResult(is_tunnel=False, tunnel_score=0.0)
        else:
            # Step 3: AI/ML DGA Analysis (Member 4)
            if self.dga_classifier:
                ml_res = self.dga_classifier.predict(query.domain)
            else:
                ml_res = MLDgaResult(is_dga=False, dga_probability=0.0)

            # Step 4: Behavioral Tunneling Detection (Member 5)
            if self.tunnel_detector:
                tunnel_res = self.tunnel_detector.analyze(query)
            else:
                tunnel_res = TunnelResult(is_tunnel=False, tunnel_score=0.0)

        # Step 5: Risk Engine Decision Calculation
        composite_score, action, rationale = RiskEngine.calculate_risk(
            intel=intel_res,
            ml=ml_res,
            tunnel=tunnel_res
        )

        resolved_ip = "0.0.0.0" if action == ActionDecision.BLOCK else "8.8.8.8"
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        decision = SecurityDecision(
            decision_id=str(uuid.uuid4()),
            query=query,
            action=action,
            composite_risk_score=composite_score,
            intel_result=intel_res,
            ml_result=ml_res,
            tunnel_result=tunnel_res,
            latency_ms=float(round(elapsed_ms, 2)),
            cache_hit=False,
            resolved_ip=resolved_ip,
            rationale=rationale
        )

        # Update cache if allowed
        if action == ActionDecision.ALLOW and self.dns_cache:
            self.dns_cache.set(query.domain, decision)

        return decision
