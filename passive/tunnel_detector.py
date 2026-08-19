import time
import math
from collections import defaultdict, deque
from typing import Dict
from shared.schemas import DNSQuery, TunnelResult

class TunnelDetector:
    """
    Behavioral DNS Tunneling Detector (60-second sliding window tracker).
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # client_ip -> deque of (timestamp, domain_len, qtype)
        self.window_tracker: Dict[str, deque] = defaultdict(deque)

    @staticmethod
    def calculate_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum([p * math.log2(p) for p in prob])

    def analyze(self, query: DNSQuery) -> TunnelResult:
        now = time.time()
        client_ip = query.client_ip
        domain = query.domain.lower()

        # Update sliding window
        tracker = self.window_tracker[client_ip]
        tracker.append((now, len(domain), query.qtype))

        # Purge entries older than sliding window
        while tracker and tracker[0][0] < now - self.window_seconds:
            tracker.popleft()

        query_count = len(tracker)
        subdomain_part = domain.split(".")[0]
        entropy = self.calculate_entropy(subdomain_part)
        query_len = len(domain)

        # Tunnel Score calculation heuristic:
        # High entropy subdomains + long payloads + high frequency + TXT queries
        tunnel_score = 0.0
        reasons = []

        if entropy > 3.9:
            tunnel_score += 40.0
            reasons.append(f"High subdomain entropy ({entropy:.2f})")

        if query_len > 45:
            tunnel_score += 35.0
            reasons.append(f"Excessive domain length ({query_len} chars)")

        if query.qtype.upper() in ["TXT", "NULL", "ANY"]:
            tunnel_score += 15.0
            reasons.append(f"Suspicious DNS query type ({query.qtype})")

        if query_count > 30:
            tunnel_score += 20.0
            reasons.append(f"High query volume burst ({query_count} queries/60s)")

        tunnel_score = min(100.0, float(round(tunnel_score, 2)))
        is_tunnel = tunnel_score >= 65.0

        rationale = ", ".join(reasons) if reasons else "Normal DNS request characteristics."

        return TunnelResult(
            is_tunnel=is_tunnel,
            tunnel_score=tunnel_score,
            entropy=float(round(entropy, 4)),
            query_length=query_len,
            reason=rationale
        )
