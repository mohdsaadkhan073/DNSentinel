import time
import threading
from typing import Optional, Dict
from shared.schemas import SecurityDecision

class DNSCache:
    """
    In-memory thread-safe TTL Cache for DNS decisions (< 5ms hit target).
    Owned by Member 2.
    """

    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl = default_ttl_seconds
        self._cache: Dict[str, tuple[SecurityDecision, float]] = {}
        self._lock = threading.Lock()

    def get(self, domain: str) -> Optional[SecurityDecision]:
        domain_key = domain.lower().strip()
        with self._lock:
            if domain_key in self._cache:
                decision, expires_at = self._cache[domain_key]
                if time.time() < expires_at:
                    return decision
                else:
                    del self._cache[domain_key]
        return None

    def set(self, domain: str, decision: SecurityDecision, ttl_seconds: Optional[int] = None):
        domain_key = domain.lower().strip()
        ttl = ttl_seconds or self.default_ttl
        expires_at = time.time() + ttl
        with self._lock:
            self._cache[domain_key] = (decision, expires_at)

    def clear(self):
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)
