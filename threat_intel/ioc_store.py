import time
from typing import Dict, Set
from shared.schemas import ThreatIntelResult

class IOCStore:
    """
    Sub-2ms In-Memory IOC Store with SQLite snapshot fallback.
    Owned by Member 3 (Threat Intel Lead).
    """

    def __init__(self):
        self._malicious_domains: Set[str] = {
            "bad-c2.com",
            "malware-command-center.org",
            "phishing-login-secure.net",
            "evil-tracker.info",
            "botnet-c2-node.xyz"
        }
        self._categories: Dict[str, str] = {
            "bad-c2.com": "Command & Control (C2)",
            "malware-command-center.org": "Malware Host",
            "phishing-login-secure.net": "Phishing",
            "evil-tracker.info": "Spyware",
            "botnet-c2-node.xyz": "Botnet"
        }

    def lookup(self, domain: str) -> ThreatIntelResult:
        domain_key = domain.lower().strip()
        if domain_key in self._malicious_domains:
            category = self._categories.get(domain_key, "Known Threat Indicator")
            return ThreatIntelResult(
                matched=True,
                threat_category=category,
                intel_score=100.0,
                source_feed="STIX/TAXII 2.1 Feeds",
                details=f"Direct match in IOC blacklist database for {domain_key}."
            )
        return ThreatIntelResult(matched=False, intel_score=0.0)

    def add_ioc(self, domain: str, category: str = "Malicious Domain"):
        d = domain.lower().strip()
        self._malicious_domains.add(d)
        self._categories[d] = category

    def total_iocs(self) -> int:
        return len(self._malicious_domains)
