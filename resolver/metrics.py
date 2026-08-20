import time
import threading
from collections import deque
from typing import Dict, Any, Optional, Union

from shared.schemas import MetricsSummary, SecurityDecision, ActionDecision, ProtocolType


class ResolverMetrics:
    """
    Lightweight, thread-safe metrics and performance instrumentation engine for DNS resolvers.
    Tracks query volumes, protocol breakdowns, rolling latency percentiles, and real-time QPS.
    Owned by Member 2 (Resolver Lead).
    """

    def __init__(self, latency_window_size: int = 1000):
        self.latency_window_size = latency_window_size
        self._lock = threading.Lock()
        self._start_time = time.time()

        # Query Counters
        self._total_queries: int = 0
        self._allowed_queries: int = 0
        self._blocked_queries: int = 0
        self._suspicious_queries: int = 0

        # Protocol Counters
        self._udp_queries: int = 0
        self._doh_queries: int = 0
        self._dtls_queries: int = 0
        self._other_protocol_queries: int = 0

        # Cache Counters
        self._cache_hits: int = 0
        self._cache_misses: int = 0

        # Upstream Counters
        self._upstream_forwarded: int = 0
        self._upstream_failures: int = 0

        # Latency Tracking
        self._total_latency_sum: float = 0.0
        self._cache_hit_latency_sum: float = 0.0
        self._min_latency_ms: float = 0.0
        self._max_latency_ms: float = 0.0
        self._recent_latencies: deque = deque(maxlen=latency_window_size)

        # Throughput & QPS Tracking (Sliding 1-second timestamp window)
        self._timestamps: deque = deque()
        self._peak_qps: float = 0.0

    def _normalize_protocol(self, protocol: Union[ProtocolType, str]) -> str:
        if isinstance(protocol, ProtocolType):
            return protocol.value.upper()
        return str(protocol).strip().upper()

    def _normalize_action(self, action: Union[ActionDecision, str]) -> str:
        if isinstance(action, ActionDecision):
            return action.value.upper()
        return str(action).strip().upper()

    def record_query(
        self,
        protocol: Union[ProtocolType, str] = "UDP",
        action: Union[ActionDecision, str] = "ALLOW",
        latency_ms: float = 0.0,
        cache_hit: bool = False,
        upstream_failed: bool = False,
    ):
        """
        Records a completed DNS resolution event into thread-safe counters and rolling buffers.
        """
        now = time.time()
        proto_str = self._normalize_protocol(protocol)
        act_str = self._normalize_action(action)
        lat = max(0.0, float(latency_ms))

        with self._lock:
            # Query Volumes
            self._total_queries += 1
            if act_str == "BLOCK":
                self._blocked_queries += 1
            elif act_str == "SUSPICIOUS":
                self._suspicious_queries += 1
            else:
                self._allowed_queries += 1

            # Protocol Breakdown
            if proto_str == "UDP":
                self._udp_queries += 1
            elif proto_str in ("DOH", "HTTPS"):
                self._doh_queries += 1
            elif proto_str in ("DTLS", "TLS"):
                self._dtls_queries += 1
            else:
                self._other_protocol_queries += 1

            # Cache Stats
            if cache_hit:
                self._cache_hits += 1
                self._cache_hit_latency_sum += lat
            else:
                self._cache_misses += 1

            # Upstream Stats
            if upstream_failed:
                self._upstream_failures += 1
            elif not cache_hit and act_str != "BLOCK":
                self._upstream_forwarded += 1

            # Latency Statistics
            self._total_latency_sum += lat
            self._recent_latencies.append(lat)

            if self._total_queries == 1:
                self._min_latency_ms = lat
                self._max_latency_ms = lat
            else:
                if lat < self._min_latency_ms:
                    self._min_latency_ms = lat
                if lat > self._max_latency_ms:
                    self._max_latency_ms = lat

            # Sliding QPS Timestamps (Prune entries older than 1.0s)
            self._timestamps.append(now)
            cutoff = now - 1.0
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()

            current_qps = float(len(self._timestamps))
            if current_qps > self._peak_qps:
                self._peak_qps = current_qps

    def record_decision(
        self,
        decision: SecurityDecision,
        protocol: Optional[Union[ProtocolType, str]] = None,
        upstream_failed: bool = False,
    ):
        """
        Convenience hook to record a SecurityDecision object.
        """
        if not decision:
            return

        proto = protocol or (decision.query.protocol if decision.query else "UDP")
        self.record_query(
            protocol=proto,
            action=decision.action,
            latency_ms=decision.latency_ms,
            cache_hit=decision.cache_hit,
            upstream_failed=upstream_failed,
        )

    def _calculate_percentiles(self) -> tuple[float, float]:
        """
        Computes p50 and p95 latency over recent bounded window.
        """
        if not self._recent_latencies:
            return 0.0, 0.0

        sorted_samples = sorted(self._recent_latencies)
        n = len(sorted_samples)

        # P50 (Median)
        p50_idx = int(0.50 * (n - 1))
        p50 = sorted_samples[p50_idx]

        # P95
        p95_idx = int(0.95 * (n - 1))
        p95 = sorted_samples[p95_idx]

        return round(p50, 2), round(p95, 2)

    def snapshot(self) -> Dict[str, Any]:
        """
        Returns a complete, typed dictionary snapshot of all current metrics.
        """
        now = time.time()
        with self._lock:
            # Prune 1s QPS window
            cutoff = now - 1.0
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()

            current_qps = float(len(self._timestamps))
            if current_qps > self._peak_qps:
                self._peak_qps = current_qps

            total_q = self._total_queries
            elapsed_sec = max(0.001, now - self._start_time)
            avg_qps = round(total_q / elapsed_sec, 2)

            avg_lat = round(self._total_latency_sum / total_q, 2) if total_q > 0 else 0.0
            cache_hit_avg_lat = (
                round(self._cache_hit_latency_sum / self._cache_hits, 2)
                if self._cache_hits > 0
                else 0.0
            )
            hit_ratio = round((self._cache_hits / total_q * 100.0), 2) if total_q > 0 else 0.0
            p50, p95 = self._calculate_percentiles()

            return {
                "total_queries": total_q,
                "allowed_queries": self._allowed_queries,
                "blocked_queries": self._blocked_queries,
                "suspicious_queries": self._suspicious_queries,
                "udp_queries": self._udp_queries,
                "doh_queries": self._doh_queries,
                "dtls_queries": self._dtls_queries,
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "cache_hit_ratio_pct": hit_ratio,
                "avg_latency_ms": avg_lat,
                "min_latency_ms": round(self._min_latency_ms, 2) if total_q > 0 else 0.0,
                "max_latency_ms": round(self._max_latency_ms, 2) if total_q > 0 else 0.0,
                "p50_latency_ms": p50,
                "p95_latency_ms": p95,
                "cache_hit_avg_latency_ms": cache_hit_avg_lat,
                "current_qps": round(current_qps, 2),
                "peak_qps": round(self._peak_qps, 2),
                "overall_avg_qps": avg_qps,
                "upstream_forwarded": self._upstream_forwarded,
                "upstream_failures": self._upstream_failures,
                "uptime_seconds": round(elapsed_sec, 2),
            }

    def summary(self) -> Dict[str, Any]:
        """
        Alias for snapshot() to return complete metrics dictionary.
        """
        return self.snapshot()

    def to_metrics_summary(self) -> MetricsSummary:
        """
        Exports metrics conforming strictly to shared.schemas.MetricsSummary.
        """
        snap = self.snapshot()
        return MetricsSummary(
            total_queries=snap["total_queries"],
            blocked_queries=snap["blocked_queries"],
            suspicious_queries=snap["suspicious_queries"],
            allowed_queries=snap["allowed_queries"],
            cache_hits=snap["cache_hits"],
            avg_latency_ms=snap["avg_latency_ms"],
            dga_detected_count=0,
            tunnels_detected_count=0,
        )

    def reset(self):
        """
        Resets all metrics counters and rolling buffers.
        """
        with self._lock:
            self._start_time = time.time()
            self._total_queries = 0
            self._allowed_queries = 0
            self._blocked_queries = 0
            self._suspicious_queries = 0
            self._udp_queries = 0
            self._doh_queries = 0
            self._dtls_queries = 0
            self._other_protocol_queries = 0
            self._cache_hits = 0
            self._cache_misses = 0
            self._upstream_forwarded = 0
            self._upstream_failures = 0
            self._total_latency_sum = 0.0
            self._cache_hit_latency_sum = 0.0
            self._min_latency_ms = 0.0
            self._max_latency_ms = 0.0
            self._recent_latencies.clear()
            self._timestamps.clear()
            self._peak_qps = 0.0


# Global singleton instance for easy import across modules
resolver_metrics = ResolverMetrics()
