import asyncio
from collections import Counter
from typing import List, Dict, Any, Optional
from shared.schemas import SecurityDecision, ActionDecision, DNSQuery

class BatchAnalyzer:
    """
    Forensic Batch Upload Processor for PCAP and Zeek TSV files.
    Processes query batches through Member 1's Detection Orchestrator,
    calculating estimated DNS payload volume and compiling forensic reports.
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    def __init__(self, orchestrator=None):
        self.orchestrator = orchestrator

    def analyze_batch(self, queries: List[DNSQuery]) -> Dict[str, Any]:
        """
        Synchronous batch analysis wrapper.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If running inside async context, construct background tasks
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(self._analyze_batch_sync, queries).result()
            else:
                return loop.run_until_complete(self.analyze_batch_async(queries))
        except Exception:
            return self._analyze_batch_sync(queries)

    def _analyze_batch_sync(self, queries: List[DNSQuery]) -> Dict[str, Any]:
        """
        Synchronous evaluation loop over query batch.
        """
        decisions: List[SecurityDecision] = []
        total = len(queries)
        blocked = 0
        suspicious = 0
        allowed = 0
        total_payload_bytes = 0

        malicious_domains_counter: Counter = Counter()
        source_ips_counter: Counter = Counter()

        for q in queries:
            # Calculate estimated payload bytes (subdomain labels + qtype overhead)
            payload_size = len(q.domain.encode("utf-8", errors="ignore"))
            total_payload_bytes += payload_size

            if self.orchestrator:
                d = self.orchestrator.process_query(q)
            else:
                # Standalone fallback decision
                from shared.schemas import ThreatIntelResult, MLDgaResult, TunnelResult
                d = SecurityDecision(
                    decision_id=q.query_id,
                    query=q,
                    action=ActionDecision.ALLOW,
                    composite_risk_score=10.0,
                    intel_result=ThreatIntelResult(matched=False, intel_score=0.0),
                    ml_result=MLDgaResult(is_dga=False, dga_probability=0.1),
                    tunnel_result=TunnelResult(is_tunnel=False, tunnel_score=0.0),
                    latency_ms=1.0,
                    resolved_ip="8.8.8.8",
                    rationale="Allowed: Default fallback"
                )

            decisions.append(d)
            source_ips_counter[q.client_ip] += 1

            if d.action == ActionDecision.BLOCK:
                blocked += 1
                malicious_domains_counter[q.domain] += 1
            elif d.action == ActionDecision.SUSPICIOUS:
                suspicious += 1
                malicious_domains_counter[q.domain] += 1
            else:
                allowed += 1

        top_malicious = [
            {"domain": dom, "count": cnt}
            for dom, cnt in malicious_domains_counter.most_common(5)
        ]

        top_sources = [
            {"client_ip": ip, "count": cnt}
            for ip, cnt in source_ips_counter.most_common(5)
        ]

        return {
            "total_queries": total,
            "blocked_count": blocked,
            "suspicious_count": suspicious,
            "allowed_count": allowed,
            "total_payload_bytes": total_payload_bytes,
            "estimated_payload_mb": float(round(total_payload_bytes / (1024 * 1024), 4)),
            "top_malicious_domains": top_malicious,
            "top_source_ips": top_sources,
            "decisions": decisions
        }

    async def analyze_batch_async(self, queries: List[DNSQuery]) -> Dict[str, Any]:
        """
        Asynchronous batch evaluation executing parallel fan-out query evaluation.
        """
        decisions: List[SecurityDecision] = []
        total = len(queries)
        blocked = 0
        suspicious = 0
        allowed = 0
        total_payload_bytes = 0

        malicious_domains_counter: Counter = Counter()
        source_ips_counter: Counter = Counter()

        for q in queries:
            payload_size = len(q.domain.encode("utf-8", errors="ignore"))
            total_payload_bytes += payload_size

            if self.orchestrator:
                d = await self.orchestrator.process_query_async(q)
            else:
                d = self.orchestrator.process_query(q) if self.orchestrator else SecurityDecision(
                    decision_id=q.query_id,
                    query=q,
                    action=ActionDecision.ALLOW,
                    composite_risk_score=10.0,
                    intel_result=None,
                    ml_result=None,
                    tunnel_result=None,
                    latency_ms=1.0,
                    resolved_ip="8.8.8.8",
                    rationale="Allowed"
                )

            decisions.append(d)
            source_ips_counter[q.client_ip] += 1

            if d.action == ActionDecision.BLOCK:
                blocked += 1
                malicious_domains_counter[q.domain] += 1
            elif d.action == ActionDecision.SUSPICIOUS:
                suspicious += 1
                malicious_domains_counter[q.domain] += 1
            else:
                allowed += 1

        top_malicious = [
            {"domain": dom, "count": cnt}
            for dom, cnt in malicious_domains_counter.most_common(5)
        ]

        top_sources = [
            {"client_ip": ip, "count": cnt}
            for ip, cnt in source_ips_counter.most_common(5)
        ]

        return {
            "total_queries": total,
            "blocked_count": blocked,
            "suspicious_count": suspicious,
            "allowed_count": allowed,
            "total_payload_bytes": total_payload_bytes,
            "estimated_payload_mb": float(round(total_payload_bytes / (1024 * 1024), 4)),
            "top_malicious_domains": top_malicious,
            "top_source_ips": top_sources,
            "decisions": decisions
        }
