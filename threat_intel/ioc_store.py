import time
from typing import Dict, Any, Optional
from shared.schemas import ThreatIntelResult
from threat_intel.threat_db import ThreatDB

def normalize_domain(domain: str) -> str:
    """
    Standardize domain names to a consistent format.
    - Convert to lowercase
    - Strip whitespaces
    - Remove http:// or https:// prefixes
    - Remove port numbers or path/query components
    - Strip trailing dots
    """
    if not domain:
        return ""
    
    # Strip whitespace and convert to lowercase
    d = domain.strip().lower()
    
    # Remove protocol prefix if present
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]
        
    # Remove port or path/query parameters
    if "/" in d:
        d = d.split("/", 1)[0]
    if ":" in d:
        d = d.split(":", 1)[0]
        
    # Strip any trailing dots
    d = d.rstrip(".")
    
    return d

class IOCStore:
    """
    Sub-2ms In-Memory IOC Store with SQLite snapshot fallback.
    Owned by Member 3 (Threat Intel Lead).
    """

    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.db = ThreatDB(db_path)
        self.db.seed_database_if_empty()
        
        # Measure only the disk-to-memory population stage (offline startup benchmark)
        start_time = time.perf_counter()
        self._store: Dict[str, Dict[str, Any]] = self.db.load_all_iocs()
        load_time_ms = (time.perf_counter() - start_time) * 1000.0
        
        print(f"[IOCStore] Initialized: loaded {len(self._store)} IOCs in {load_time_ms:.2f}ms.")

    def lookup(self, domain: str) -> ThreatIntelResult:
        """
        Check if a domain is a known IOC. Supports exact match and parent-domain matching.
        Example: if evil.com is blocked, sub.evil.com matches.
        """
        normalized = normalize_domain(domain)
        if not normalized:
            return ThreatIntelResult(matched=False, intel_score=0.0)

        # Generate subdomain check order, from most specific to least specific
        # e.g., "sub.evil.com" -> ["sub.evil.com", "evil.com"]
        parts = normalized.split(".")
        for i in range(len(parts) - 1):
            current = ".".join(parts[i:])
            if current in self._store:
                entry = self._store[current]
                parent_details = entry.get("details", "")
                details_str = f"Match found (parent block: {current}). Base details: {parent_details}" if current != normalized else parent_details
                return ThreatIntelResult(
                    matched=True,
                    threat_category=entry.get("category", "Command & Control (C2)"),
                    intel_score=entry.get("confidence", 100.0),
                    source_feed=entry.get("source", "STIX/TAXII Feed"),
                    details=details_str
                )

        # Finally, check the last single label
        if normalized in self._store:
            entry = self._store[normalized]
            return ThreatIntelResult(
                matched=True,
                threat_category=entry.get("category", "Command & Control (C2)"),
                intel_score=entry.get("confidence", 100.0),
                source_feed=entry.get("source", "STIX/TAXII Feed"),
                details=entry.get("details", f"Direct match found")
            )

        return ThreatIntelResult(matched=False, intel_score=0.0)

    def check_domain(self, domain: str) -> ThreatIntelResult:
        """
        Alias for lookup to match alternate naming conventions in the project.
        """
        return self.lookup(domain)

    def add_ioc(self, domain: str, category: str = "Malicious Domain", confidence: float = 100.0, source: str = "STIX/TAXII 2.1 Feeds", details: str = "Added via API"):
        """
        Dynamically add an IOC to the in-memory store and persist it in the SQLite DB.
        """
        d = normalize_domain(domain)
        if d:
            self._store[d] = {
                "category": category,
                "confidence": confidence,
                "source": source,
                "details": details
            }
            # Persist to local database
            self.db.add_iocs_batch([(d, category, confidence, source, details)])

    def total_iocs(self) -> int:
        """
        Return the total number of IOCs loaded in the store.
        """
        return len(self._store)
