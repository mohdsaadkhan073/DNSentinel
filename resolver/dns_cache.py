import os
import time
import threading
from typing import Optional, Dict, Tuple, Any
from shared.schemas import SecurityDecision

DEFAULT_CACHE_TTL: float = float(os.getenv("DNS_CACHE_DEFAULT_TTL", "300.0"))
DEFAULT_MAX_ENTRIES: int = int(os.getenv("DNS_CACHE_MAX_ENTRIES", "10000"))


class DNSCache:
    """
    In-memory thread-safe TTL Cache for DNS decisions (< 5ms hit target).
    Supports domain normalization, dynamic lazy TTL expiration, defensive copying,
    and capacity bounds.
    Owned by Member 2 (Resolver Lead).
    """

    def __init__(
        self,
        default_ttl_seconds: float = DEFAULT_CACHE_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        self.default_ttl = default_ttl_seconds
        self.max_entries = max_entries
        self._cache: Dict[str, Tuple[SecurityDecision, float]] = {}
        self._lock = threading.Lock()
        self._hits: int = 0
        self._misses: int = 0

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """
        Normalizes domain string by lowercasing, stripping whitespace, and removing trailing dot.
        """
        if not domain:
            return ""
        return domain.strip().lower().rstrip(".")

    def get(self, domain: str) -> Optional[SecurityDecision]:
        """
        Retrieves a cached SecurityDecision if present and unexpired.
        Returns a defensive deep copy to prevent in-place mutation of cached state.
        """
        domain_key = self._normalize_domain(domain)
        if not domain_key:
            with self._lock:
                self._misses += 1
            return None

        with self._lock:
            if domain_key in self._cache:
                decision, expires_at = self._cache[domain_key]
                if time.time() < expires_at:
                    self._hits += 1
                    # Defensive copy: prevent caller mutations (e.g. Orchestrator) from corrupting cache
                    if hasattr(decision, "model_copy"):
                        return decision.model_copy(deep=True)
                    else:
                        import copy
                        return copy.deepcopy(decision)
                else:
                    # Lazy expiration on access
                    del self._cache[domain_key]

            self._misses += 1
            return None

    def set(
        self,
        domain: str,
        decision: SecurityDecision,
        ttl_seconds: Optional[float] = None,
    ):
        """
        Stores a SecurityDecision in cache with calculated expiration timestamp.
        Enforces maximum capacity with FIFO eviction.
        """
        domain_key = self._normalize_domain(domain)
        if not domain_key or decision is None:
            return

        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = time.time() + ttl

        # Defensive copy when storing into cache
        stored_decision = decision.model_copy(deep=True) if hasattr(decision, "model_copy") else decision

        with self._lock:
            # Capacity guard: Evict oldest entry if limit reached and key is new
            if len(self._cache) >= self.max_entries and domain_key not in self._cache:
                try:
                    oldest_key = next(iter(self._cache))
                    del self._cache[oldest_key]
                except (StopIteration, KeyError):
                    pass

            self._cache[domain_key] = (stored_decision, expires_at)

    def clear(self):
        """
        Clears all entries and resets metrics.
        """
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def size(self) -> int:
        """
        Returns current number of cached entries.
        """
        with self._lock:
            return len(self._cache)

    def prune_expired(self) -> int:
        """
        Optional helper to clean all expired entries in bulk.
        Returns count of purged entries.
        """
        now = time.time()
        purged = 0
        with self._lock:
            expired_keys = [k for k, (_, exp) in self._cache.items() if now >= exp]
            for k in expired_keys:
                del self._cache[k]
                purged += 1
        return purged

    @property
    def stats(self) -> Dict[str, Any]:
        """
        Returns lightweight cache telemetry statistics.
        """
        with self._lock:
            total = self._hits + self._misses
            hit_ratio = (self._hits / total * 100.0) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "max_entries": self.max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "hit_ratio_pct": round(hit_ratio, 2),
                "default_ttl": self.default_ttl,
            }
