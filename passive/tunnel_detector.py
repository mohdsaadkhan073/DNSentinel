import math
import time
from typing import Optional, List, Tuple
from shared.schemas import DNSQuery, TunnelResult
from passive.volume_tracker import VolumeTracker

class TunnelDetector:
    """
    Production-ready Behavioral DNS Tunneling Detector.
    Evaluates active behavioral metrics (Subdomain Shannon Entropy, Label Length,
    High-Payload QTYPE Penalties, and 60s Sliding-Window Query Volume).
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    def __init__(self, window_seconds: int = 60, volume_tracker: Optional[VolumeTracker] = None):
        self.window_seconds = window_seconds
        self.volume_tracker = volume_tracker or VolumeTracker(window_seconds=window_seconds)

    @staticmethod
    def calculate_entropy(s: str) -> float:
        """
        Calculates Shannon Entropy for a given string in bits per character.
        H(X) = - sum(P(x) * log2(P(x)))
        """
        if not s:
            return 0.0
        length = len(s)
        counts = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(round(entropy, 4))

    @staticmethod
    def extract_subdomain_prefix(domain: str) -> str:
        """
        Extracts the subdomain prefix (excluding the registered root domain and TLD).
        e.g., 'a1b2c3d4e5f6.attacker.com' -> 'a1b2c3d4e5f6'
        """
        if not domain:
            return ""
        clean_domain = domain.strip().lower().rstrip(".")
        parts = clean_domain.split(".")
        if len(parts) <= 2:
            # e.g., 'example.com' -> return the label before TLD 'example'
            return parts[0] if parts else ""
        # Return all subdomain labels joined together
        return "".join(parts[:-2])

    def analyze(self, query: DNSQuery) -> TunnelResult:
        """
        Analyzes incoming DNS query against 4 active behavioral tunneling heuristics (< 5ms SLA):
        1. Subdomain Shannon Entropy (H > 4.2 -> +35 pts)
        2. Subdomain Prefix Length (L > 30 -> +30 pts)
        3. High-Payload QTYPE Weighting (TXT -> +20, NULL -> +30, CNAME -> +15 pts)
        4. Sliding-Window Volume Rate (> 50 queries/60s -> +25 pts)
        """
        start_time = time.perf_counter()
        domain = query.domain.strip().lower().rstrip(".")
        client_ip = query.client_ip or "127.0.0.1"
        qtype = query.qtype.upper() if query.qtype else "A"

        # Record query in 60s volume tracker
        timestamp_sec = query.timestamp.timestamp() if hasattr(query.timestamp, "timestamp") else time.time()
        query_count, total_bytes = self.volume_tracker.record_query(
            client_ip=client_ip,
            domain=domain,
            qtype=qtype,
            timestamp=timestamp_sec
        )

        subdomain_prefix = self.extract_subdomain_prefix(domain)
        entropy = self.calculate_entropy(subdomain_prefix if subdomain_prefix else domain)
        subdomain_len = len(subdomain_prefix)
        full_query_len = len(domain)

        tunnel_score = 0.0
        reasons: List[str] = []

        # Heuristic 1: Subdomain Shannon Entropy (H > 4.2 -> +35 pts)
        if entropy > 4.2:
            tunnel_score += 35.0
            reasons.append(f"High subdomain entropy ({entropy:.2f} > 4.2)")
        elif entropy > 3.6:
            tunnel_score += 15.0
            reasons.append(f"Elevated subdomain entropy ({entropy:.2f})")

        # Heuristic 2: Subdomain Prefix Length (L > 30 -> +30 pts)
        if subdomain_len > 30:
            tunnel_score += 30.0
            reasons.append(f"Excessive subdomain prefix length ({subdomain_len} > 30 chars)")
        elif full_query_len > 45:
            tunnel_score += 20.0
            reasons.append(f"Long query string ({full_query_len} chars)")

        # Heuristic 3: High-Payload QTYPE Weighting (NULL -> +30, TXT -> +20, CNAME -> +15 pts)
        if qtype == "NULL":
            tunnel_score += 30.0
            reasons.append("High-payload record type (NULL)")
        elif qtype == "TXT":
            tunnel_score += 20.0
            reasons.append("High-payload record type (TXT)")
        elif qtype == "CNAME":
            tunnel_score += 15.0
            reasons.append("Potential CNAME tunnel encoding")

        # Heuristic 4: Sliding-Window Volume Rate (> 50 queries/60s -> +25 pts)
        if query_count > 50:
            tunnel_score += 25.0
            reasons.append(f"Exfiltration volume burst ({query_count} queries/60s window)")
        elif query_count > 30:
            tunnel_score += 15.0
            reasons.append(f"Elevated query rate ({query_count} queries/60s)")

        tunnel_score = min(100.0, float(round(tunnel_score, 2)))
        is_tunnel = tunnel_score >= 60.0

        rationale = "; ".join(reasons) if reasons else "Normal DNS request characteristics."

        return TunnelResult(
            is_tunnel=is_tunnel,
            tunnel_score=tunnel_score,
            entropy=float(round(entropy, 4)),
            query_length=full_query_len,
            reason=rationale
        )

    def check_tunneling(self, query: DNSQuery) -> TunnelResult:
        """Alias for analyze for backward compatibility."""
        return self.analyze(query)
