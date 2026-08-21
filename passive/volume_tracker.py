import time
import threading
import uuid
from collections import defaultdict, deque
from typing import Dict, Tuple, List, Optional

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

class VolumeTracker:
    """
    Thread-safe 60-second sliding-window DNS query volume and payload size tracker.
    Supports optional Redis ZSET backend for multi-worker cluster synchronization,
    with automatic silent fallback to thread-safe in-memory deques.
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    def __init__(self, window_seconds: int = 60, redis_host: str = "localhost", redis_port: int = 6379, redis_db: int = 0):
        self.window_seconds = window_seconds
        self._tracker: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        
        # Redis cluster integration initialization
        self.redis_client = None
        self.use_redis = False

        if HAS_REDIS:
            try:
                r = redis.Redis(host=redis_host, port=redis_port, db=redis_db, socket_timeout=0.5)
                r.ping()
                self.redis_client = r
                self.use_redis = True
                print(f"[VolumeTracker] [REDIS OK] Connected to Redis at {redis_host}:{redis_port} (Multi-Worker Cluster Mode Active).")
            except Exception as e:
                self.use_redis = False
                print(f"[VolumeTracker] [OFFLINE MODE] Redis unavailable on {redis_host}:{redis_port}. Using Thread-Safe In-Memory Tracker.")
        else:
            print("[VolumeTracker] [OFFLINE MODE] redis-py module not installed. Using Thread-Safe In-Memory Tracker.")

    def record_query(self, client_ip: str, domain: str, qtype: str, timestamp: Optional[float] = None) -> Tuple[int, int]:
        """
        Records a query for client_ip and purges expired entries outside sliding window.
        Returns tuple of: (query_count_in_window, total_payload_bytes_in_window)
        """
        now = timestamp if timestamp is not None else time.time()
        payload_bytes = len(domain.encode("utf-8", errors="ignore"))

        if self.use_redis and self.redis_client:
            try:
                key = f"vol_tracker:{client_ip}"
                cutoff = now - self.window_seconds
                member_val = f"{now}:{uuid.uuid4().hex[:8]}:{payload_bytes}:{domain[:30]}"

                pipe = self.redis_client.pipeline()
                pipe.zremrangebyscore(key, "-inf", cutoff)
                pipe.zadd(key, {member_val: now})
                pipe.zcard(key)
                pipe.expire(key, self.window_seconds * 2)
                results = pipe.execute()

                query_count = results[2]
                total_bytes = query_count * payload_bytes  # Approximate payload estimation in Redis mode
                return query_count, total_bytes
            except Exception:
                # Fail open to in-memory fallback if Redis connection fails mid-operation
                pass

        with self._lock:
            client_queue = self._tracker[client_ip]
            client_queue.append((now, payload_bytes, qtype.upper(), domain))

            # Purge entries older than sliding window
            cutoff = now - self.window_seconds
            while client_queue and client_queue[0][0] < cutoff:
                client_queue.popleft()

            query_count = len(client_queue)
            total_bytes = sum(entry[1] for entry in client_queue)

        return query_count, total_bytes

    def get_stats(self, client_ip: str, timestamp: Optional[float] = None) -> Tuple[int, int]:
        """
        Returns (query_count, total_bytes) for client_ip within current window without adding a record.
        """
        now = timestamp if timestamp is not None else time.time()
        cutoff = now - self.window_seconds

        if self.use_redis and self.redis_client:
            try:
                key = f"vol_tracker:{client_ip}"
                self.redis_client.zremrangebyscore(key, "-inf", cutoff)
                query_count = self.redis_client.zcard(key)
                return query_count, query_count * 30
            except Exception:
                pass

        with self._lock:
            client_queue = self._tracker.get(client_ip)
            if not client_queue:
                return 0, 0

            # Purge expired
            while client_queue and client_queue[0][0] < cutoff:
                client_queue.popleft()

            return len(client_queue), sum(entry[1] for entry in client_queue)

    def clear(self):
        """Clears all tracking queues."""
        if self.use_redis and self.redis_client:
            try:
                keys = self.redis_client.keys("vol_tracker:*")
                if keys:
                    self.redis_client.delete(*keys)
            except Exception:
                pass
        with self._lock:
            self._tracker.clear()

