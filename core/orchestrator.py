import asyncio
import time
import uuid
from typing import Optional, Any
from shared.schemas import (
    DNSQuery,
    SecurityDecision,
    ActionDecision,
    ThreatIntelResult,
    MLDgaResult,
    TunnelResult
)
from shared.config import DETECTION_TIMEOUT_SEC
from core.risk_engine import RiskEngine

class Orchestrator:
    """
    Parallel orchestration engine coordinating Threat Intel, ML DGA, and Tunneling detectors.
    Owned by Member 1 (Team Lead & Core Security Architect).
    Supports synchronous and asynchronous parallel fan-out (< 25ms timeout SLA).
    """

    def __init__(self, ioc_store=None, dga_classifier=None, tunnel_detector=None, dns_cache=None):
        self.ioc_store = ioc_store
        self.dga_classifier = dga_classifier
        self.tunnel_detector = tunnel_detector
        self.dns_cache = dns_cache

    def process_query(self, query: DNSQuery) -> SecurityDecision:
        """
        Synchronous evaluation pipeline.
        Checks cache -> Threat Intel -> ML DGA & Tunneling -> Risk Engine decision.
        """
        start_time = time.perf_counter()

        # Step 1: Check DNS Cache (< 5ms SLA)
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
            intel_res = self._call_module_sync(self.ioc_store, "lookup", query.domain, fallback=ThreatIntelResult(matched=False, intel_score=0.0))
        else:
            intel_res = ThreatIntelResult(matched=False, intel_score=0.0)

        # Fast path if Threat Intel matched
        if intel_res.matched:
            ml_res = MLDgaResult(is_dga=False, dga_probability=0.0)
            tunnel_res = TunnelResult(is_tunnel=False, tunnel_score=0.0)
        else:
            # Step 3: AI/ML DGA Analysis (Member 4)
            if self.dga_classifier:
                ml_res = self._call_module_sync(self.dga_classifier, "predict", query.domain, fallback=MLDgaResult(is_dga=False, dga_probability=0.0))
            else:
                ml_res = MLDgaResult(is_dga=False, dga_probability=0.0)

            # Step 4: Behavioral Tunneling Detection (Member 5)
            if self.tunnel_detector:
                tunnel_res = self._call_module_sync(self.tunnel_detector, "analyze", query, fallback=TunnelResult(is_tunnel=False, tunnel_score=0.0))
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

        if self.dns_cache:
            self.dns_cache.set(query.domain, decision)

        return decision

    async def process_query_async(self, query: DNSQuery, timeout_sec: float = DETECTION_TIMEOUT_SEC) -> SecurityDecision:
        """
        Asynchronous parallel fan-out pipeline with strict timeout ceiling (default 25ms SLA).
        Concurrently executes Threat Intel, ML DGA, and Tunneling checks using asyncio.gather.
        """
        start_time = time.perf_counter()

        # Step 1: Check DNS Cache (< 5ms SLA)
        if self.dns_cache:
            cached_result = self.dns_cache.get(query.domain)
            if cached_result:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                cached_result.query = query
                cached_result.cache_hit = True
                cached_result.latency_ms = float(round(elapsed_ms, 2))
                return cached_result

        # Step 2: Asynchronous parallel fan-out
        async def run_intel() -> ThreatIntelResult:
            if not self.ioc_store:
                return ThreatIntelResult(matched=False, intel_score=0.0)
            return await self._call_module_async(self.ioc_store, "lookup", query.domain, fallback=ThreatIntelResult(matched=False, intel_score=0.0))

        async def run_ml() -> MLDgaResult:
            if not self.dga_classifier:
                return MLDgaResult(is_dga=False, dga_probability=0.0)
            return await self._call_module_async(self.dga_classifier, "predict", query.domain, fallback=MLDgaResult(is_dga=False, dga_probability=0.0))

        async def run_tunnel() -> TunnelResult:
            if not self.tunnel_detector:
                return TunnelResult(is_tunnel=False, tunnel_score=0.0)
            return await self._call_module_async(self.tunnel_detector, "analyze", query, fallback=TunnelResult(is_tunnel=False, tunnel_score=0.0))

        try:
            results = await asyncio.wait_for(
                asyncio.gather(run_intel(), run_ml(), run_tunnel(), return_exceptions=True),
                timeout=timeout_sec
            )
            intel_res = results[0] if isinstance(results[0], ThreatIntelResult) else ThreatIntelResult(matched=False, intel_score=0.0)
            ml_res = results[1] if isinstance(results[1], MLDgaResult) else MLDgaResult(is_dga=False, dga_probability=0.0)
            tunnel_res = results[2] if isinstance(results[2], TunnelResult) else TunnelResult(is_tunnel=False, tunnel_score=0.0)
        except asyncio.TimeoutError:
            # High-throughput SLA protection timeout fallback
            intel_res = ThreatIntelResult(matched=False, intel_score=0.0)
            ml_res = MLDgaResult(is_dga=False, dga_probability=0.0)
            tunnel_res = TunnelResult(is_tunnel=False, tunnel_score=0.0)

        # Step 3: Risk Engine Decision Calculation
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

        if self.dns_cache:
            self.dns_cache.set(query.domain, decision)

        return decision

    def _call_module_sync(self, obj: Any, method_name: str, arg: Any, fallback: Any) -> Any:
        try:
            sync_method = getattr(obj, f"{method_name}_sync", None)
            if sync_method:
                return sync_method(arg)
            method = getattr(obj, method_name, None)
            if method:
                res = method(arg)
                if asyncio.iscoroutine(res):
                    res.close()  # close unawaited coroutine if sync fallback called
                    return fallback
                return res
        except Exception:
            pass
        return fallback


    async def _call_module_async(self, obj: Any, method_name: str, arg: Any, fallback: Any) -> Any:
        try:
            async_method = getattr(obj, f"{method_name}_async", None)
            if async_method and asyncio.iscoroutinefunction(async_method):
                return await async_method(arg)

            method = getattr(obj, method_name, None)
            if method:
                if asyncio.iscoroutinefunction(method):
                    return await method(arg)
                else:
                    res = method(arg)
                    if asyncio.iscoroutine(res):
                        return await res
                    return res
        except Exception:
            pass
        return fallback

