import time
from typing import Dict, List, Any, Tuple, Optional
from threat_intel.ioc_store import IOCStore, normalize_domain

# Priority ranking for category conflicts (higher rank takes precedence)
CATEGORY_PRIORITY = {
    "Command & Control (C2)": 6,
    "Botnet": 5,
    "Spyware": 4,
    "Malware Host": 3,
    "Phishing": 2,
    "Malicious Domain": 1
}

def resolve_category(cat1: str, cat2: str) -> str:
    """
    Resolve category conflict based on severity rankings.
    """
    p1 = CATEGORY_PRIORITY.get(cat1, 0)
    p2 = CATEGORY_PRIORITY.get(cat2, 0)
    return cat1 if p1 >= p2 else cat2

class ThreatAggregator:
    """
    Aggregation and deduplication engine for multiple threat-intelligence feeds.
    Owned by Member 3 (Threat Intel Lead).
    """

    def __init__(self, ioc_store: IOCStore):
        self.ioc_store = ioc_store
        self.db = ioc_store.db

    def aggregate_feeds(self, feeds_data: Dict[str, List[Dict[str, Any]]]) -> List[Tuple[str, str, float, str, str]]:
        """
        Aggregate and deduplicate multiple feeds.
        feeds_data: dict mapping feed_name -> list of parsed indicators
        Each indicator is a dict: {
            "domain": str,
            "category": str,
            "confidence": float,
            "details": str
        }
        Returns a list of tuples: (domain, category, confidence, source_feed, details)
        """
        aggregated: Dict[str, Dict[str, Any]] = {}

        for feed_name, indicators in feeds_data.items():
            if not indicators:
                continue

            for ind in indicators:
                raw_domain = ind.get("domain")
                if not raw_domain:
                    continue
                
                domain = normalize_domain(raw_domain)
                if not domain:
                    continue

                category = ind.get("category", "Malicious Domain")
                
                # Robust float conversion fallback
                confidence_raw = ind.get("confidence")
                try:
                    confidence = float(confidence_raw) if confidence_raw is not None else 80.0
                except (ValueError, TypeError):
                    confidence = 80.0
                    
                details = ind.get("details") or f"Indicator from {feed_name}"

                if domain not in aggregated:
                    aggregated[domain] = {
                        "category": category,
                        "confidence": confidence,
                        "sources": {feed_name},
                        "details": details
                    }
                else:
                    entry = aggregated[domain]
                    
                    # 1. Source Attribution: add source feed to the set
                    entry["sources"].add(feed_name)
                    
                    # 2. Confidence Handling: take the maximum confidence score
                    prev_conf = entry["confidence"]
                    entry["confidence"] = max(prev_conf, confidence)
                    
                    # 3. Category Conflict Resolution: use priority ranking
                    entry["category"] = resolve_category(entry["category"], category)
                    
                    # 4. Details: prefer details of the source with higher confidence
                    if confidence > prev_conf:
                        entry["details"] = details

        # Convert back to list of tuples for SQLite batch writing
        result_tuples = []
        for domain, entry in aggregated.items():
            # Format source_feed as a sorted, comma-separated string of active sources
            source_feed_str = ", ".join(sorted(list(entry["sources"])))
            result_tuples.append((
                domain,
                entry["category"],
                entry["confidence"],
                source_feed_str,
                entry["details"]
            ))

        return result_tuples

    def update_store_and_db(
        self, 
        aggregated_iocs: List[Tuple[str, str, float, str, str]], 
        feed_statuses: Dict[str, Dict[str, Any]]
    ):
        """
        Save the aggregated list to SQLite and synchronize the in-memory store.
        If any part of the database write fails, the database is rolled back, 
        and the in-memory cache is NOT modified (retaining old valid IOC data).
        """
        try:
            # 1. Batch insert into SQLite DB
            if aggregated_iocs:
                self.db.add_iocs_batch(aggregated_iocs)
            
            # 2. Re-load the in-memory cache from SQLite DB to maintain synchronization
            # Only swap the memory store pointer if database writes succeeded
            new_store = self.db.load_all_iocs()
            self.ioc_store._store = new_store
            
        except Exception as e:
            # If update failed, reflect the failure across the related feeds
            for feed_name in feed_statuses:
                feed_statuses[feed_name]["status"] = "FAILED"
                feed_statuses[feed_name]["error_message"] = f"Atomic update failed: {e}"
            raise RuntimeError(f"Atomic update failed: {e}")
            
        finally:
            # 3. Record feed synchronization health metrics in SQLite
            for feed_name, status_info in feed_statuses.items():
                self.db.update_feed_health(
                    feed_name=feed_name,
                    status=status_info.get("status", "UNKNOWN"),
                    count=status_info.get("count", 0),
                    error_msg=status_info.get("error_message"),
                    latency_ms=status_info.get("latency_ms", 0.0)
                )
