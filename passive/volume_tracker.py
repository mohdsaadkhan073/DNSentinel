import time
import threading
from collections import defaultdict, deque
from typing import Dict, Tuple, List, Optional

class VolumeTracker:
    """
    Thread-safe 60-second sliding-window DNS query volume and payload size tracker.
    Tracks query rate per client IP to detect covert DNS data exfiltration attempts.
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # client_ip -> deque of (timestamp, payload_bytes, qtype, domain)
        self._tracker: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def record_query(self, client_ip: str, domain: str, qtype: str, timestamp: Optional[float] = None) -> Tuple[int, int]:
        """
        Records a query for the client_ip and purges expired entries outside the sliding window.
        Returns a tuple of: (query_count_in_window, total_payload_bytes_in_window)
        """
        now = timestamp if timestamp is not None else time.time()
        payload_bytes = len(domain.encode("utf-8", errors="ignore"))

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
        with self._lock:
            self._tracker.clear()
