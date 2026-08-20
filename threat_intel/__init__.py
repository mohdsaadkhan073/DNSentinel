"""
Threat Intelligence module: STIX 2.1 JSON parser, TAXII 2.1 client, and sub-2ms IOC Store.
Owned by Member 3 (Threat Intel Lead).
"""

from threat_intel.ioc_store import IOCStore, normalize_domain
from threat_intel.stix_parser import STIXParser
from threat_intel.taxii_client import TAXIIClient
from threat_intel.threat_db import ThreatDB
from threat_intel.aggregator import ThreatAggregator
from threat_intel.background_worker import BackgroundWorker

__all__ = [
    "IOCStore",
    "normalize_domain",
    "STIXParser",
    "TAXIIClient",
    "ThreatDB",
    "ThreatAggregator",
    "BackgroundWorker",
]
