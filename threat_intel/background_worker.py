import threading
import time
from typing import Dict, Any, List, Optional
from threat_intel.taxii_client import TAXIIClient
from threat_intel.aggregator import ThreatAggregator

class BackgroundWorker:
    """
    Background worker thread for periodic threat feed synchronization.
    Owned by Member 3 (Threat Intel Lead).
    """
    def __init__(
        self, 
        aggregator: ThreatAggregator, 
        taxii_clients: Dict[str, TAXIIClient], 
        interval_seconds: float = 60.0
    ):
        self.aggregator = aggregator
        self.taxii_clients = taxii_clients
        self.interval_seconds = interval_seconds
        
        self._shutdown_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()  # Prevent overlapping sync loops
        self._is_running = False

    def start(self):
        """
        Starts the daemonized worker thread.
        """
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._shutdown_event.clear()
            self._thread = threading.Thread(target=self._run_loop, name="ThreatIntelWorker", daemon=True)
            self._thread.start()
            print("[ThreatIntelWorker] Background update thread started.")

    def stop(self):
        """
        Gracefully triggers shutdown and joins the worker thread.
        """
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False
            self._shutdown_event.set()
            
        if self._thread:
            self._thread.join(timeout=5.0)
            print("[ThreatIntelWorker] Background update thread stopped.")

    def is_alive(self) -> bool:
        """
        Check if the worker thread is running.
        """
        return self._thread is not None and self._thread.is_alive()

    def _run_loop(self):
        """
        Executes feed updates periodically according to the interval configuration.
        """
        while not self._shutdown_event.is_set():
            self.sync_all_feeds()
            
            # Stepwise sleep to allow rapid stop interrupts
            elapsed = 0.0
            while elapsed < self.interval_seconds:
                if self._shutdown_event.is_set():
                    break
                time.sleep(0.1)
                elapsed += 0.1

    def sync_all_feeds(self) -> Dict[str, Dict[str, Any]]:
        """
        Polls and updates all configured TAXII feeds sequentially.
        Ensures execution exceptions on one feed do not affect other feeds.
        Prevent overlapping runs using non-blocking lock acquires.
        """
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            print("[ThreatIntelWorker] Warning: Overlapping feed update skipped.")
            return {}
            
        statuses = {}
        try:
            all_indicators = []
            feed_indicators_map = {}
            
            # Initialize empty list for each feed to aggregate correctly
            for feed_name in self.taxii_clients:
                feed_indicators_map[feed_name] = []
                
            for feed_name, client in self.taxii_clients.items():
                if self._shutdown_event.is_set():
                    break
                    
                try:
                    print(f"[ThreatIntelWorker] Syncing feed: {feed_name}...")
                    indicators, status = client.poll_and_parse_feed()
                    statuses[feed_name] = status
                    
                    if status["status"] == "SUCCESS":
                        all_indicators.extend(indicators)
                        feed_indicators_map[feed_name] = indicators
                        print(f"[ThreatIntelWorker] {feed_name} successfully polled: {len(indicators)} indicators.")
                    else:
                        print(f"[ThreatIntelWorker] {feed_name} failed: {status.get('error_message')}")
                        
                except Exception as e:
                    # Isolate exceptions: one feed failure must not impact others
                    statuses[feed_name] = {
                        "status": "FAILED",
                        "count": 0,
                        "error_message": f"Worker feed loop error: {str(e)}",
                        "latency_ms": 0.0
                    }
                    print(f"[ThreatIntelWorker] Error polling {feed_name}: {e}")

            # Perform atomic SQLite commit and swap memory store if indicators were retrieved
            if all_indicators:
                try:
                    aggregated = self.aggregator.aggregate_feeds(feed_indicators_map)
                    self.aggregator.update_store_and_db(aggregated, statuses)
                    print("[ThreatIntelWorker] Database and memory cache updated atomically.")
                except Exception as e:
                    print(f"[ThreatIntelWorker] Atomic store update failed: {e}")
            else:
                # No new indicators, but we still write/log feed failure status health info to SQLite
                for feed_name, status in statuses.items():
                    self.aggregator.db.update_feed_health(
                        feed_name=feed_name,
                        status=status.get("status", "FAILED"),
                        count=status.get("count", 0),
                        error_msg=status.get("error_message"),
                        latency_ms=status.get("latency_ms", 0.0)
                    )
                    
        finally:
            self._lock.release()
            
        return statuses
