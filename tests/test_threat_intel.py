import os
import time
import pytest
from threat_intel.ioc_store import IOCStore, normalize_domain
from threat_intel.threat_db import ThreatDB
from shared.schemas import ThreatIntelResult

@pytest.fixture
def test_db_path():
    path = "test_threat_intelligence.db"
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass

def test_domain_normalization():
    # Test cases for lowercase
    assert normalize_domain("EVIL.com") == "evil.com"
    # Test cases for whitespace
    assert normalize_domain("  evil.com  ") == "evil.com"
    # Test cases for http/https prefixes
    assert normalize_domain("http://evil.com") == "evil.com"
    assert normalize_domain("https://evil.com") == "evil.com"
    # Test cases for paths and ports
    assert normalize_domain("http://evil.com/some/path?param=1") == "evil.com"
    assert normalize_domain("evil.com:8443/path") == "evil.com"
    # Test cases for trailing dots
    assert normalize_domain("evil.com.") == "evil.com"
    # Test case for empty domain
    assert normalize_domain("") == ""
    assert normalize_domain(None) == ""

def test_ioc_store_lookup_exact(test_db_path):
    store = IOCStore(db_path=test_db_path)
    
    # Check default IOCs
    res1 = store.lookup("bad-c2.com")
    assert res1.matched is True
    assert res1.threat_category == "Command & Control (C2)"
    assert res1.intel_score == 100.0
    
    # Check uppercase query
    res2 = store.lookup("BAD-C2.COM")
    assert res2.matched is True
    
    # Check clean domain query
    res3 = store.lookup("google.com")
    assert res3.matched is False
    assert res3.intel_score == 0.0

def test_ioc_store_lookup_parent(test_db_path):
    store = IOCStore(db_path=test_db_path)
    
    # Subdomain of default IOC
    res1 = store.lookup("sub.bad-c2.com")
    assert res1.matched is True
    assert "bad-c2.com" in res1.details
    
    # Multi-level subdomain of default IOC
    res2 = store.lookup("a.b.c.bad-c2.com")
    assert res2.matched is True
    
    # Mismatch checking (substring verification)
    # "notbad-c2.com" must NOT match "bad-c2.com"
    res3 = store.lookup("notbad-c2.com")
    assert res3.matched is False

def test_ioc_store_check_domain_alias(test_db_path):
    store = IOCStore(db_path=test_db_path)
    res = store.check_domain("bad-c2.com")
    assert res.matched is True

def test_ioc_store_add_ioc(test_db_path):
    store = IOCStore(db_path=test_db_path)
    initial_count = store.total_iocs()
    
    # Add a custom IOC
    store.add_ioc(
        domain="new-malicious-site.net",
        category="Phishing",
        confidence=85.0,
        source="Custom Test Feed",
        details="Discovered during automated test"
    )
    
    assert store.total_iocs() == initial_count + 1
    
    # Test exact match of new IOC
    res = store.lookup("new-malicious-site.net")
    assert res.matched is True
    assert res.threat_category == "Phishing"
    assert res.intel_score == 85.0
    assert res.source_feed == "Custom Test Feed"
    
    # Test subdomain match of new IOC
    res_sub = store.lookup("login.new-malicious-site.net")
    assert res_sub.matched is True
    assert res_sub.intel_score == 85.0

def test_sqlite_db_seeding_and_performance(test_db_path):
    # 1. Initialize store with test db (triggers tables & seeding)
    store = IOCStore(db_path=test_db_path)
    total_loaded = store.total_iocs()
    assert total_loaded >= 50000
    
    # 2. Benchmark pre-seeded startup load time (simulating production reboot)
    start = time.perf_counter()
    store_second_boot = IOCStore(db_path=test_db_path)
    load_time_ms = (time.perf_counter() - start) * 1000.0
    
    # Verify startup load time is well under 200ms
    assert load_time_ms < 200.0
    
    # 3. Verify defaults are loaded and check exact lookup
    res_default = store_second_boot.lookup("bad-c2.com")
    assert res_default.matched is True
    assert res_default.threat_category == "Command & Control (C2)"
    
    # 4. Verify synthetic/demo indicators match requirements
    db = ThreatDB(test_db_path)
    iocs = db.load_all_iocs()
    
    synth_domains = [d for d in iocs.keys() if d.startswith("synth-")]
    assert len(synth_domains) > 0
    sample_domain = synth_domains[0]
    
    res_sample = store_second_boot.lookup(sample_domain)
    assert res_sample.matched is True
    assert res_sample.source_feed == "demo_seed"
    assert res_sample.details == "Synthetic development/demo IOC"

def test_feed_health_tracking(test_db_path):
    db = ThreatDB(test_db_path)
    
    # Initial status is empty
    health = db.get_feed_health()
    assert len(health) == 0
    
    # Update health info
    db.update_feed_health(
        feed_name="Abuse.ch URLhaus",
        status="SUCCESS",
        count=150,
        error_msg=None,
        latency_ms=250.5
    )
    
    health = db.get_feed_health()
    assert len(health) == 1
    assert health[0]["feed_name"] == "Abuse.ch URLhaus"
    assert health[0]["status"] == "SUCCESS"
    assert health[0]["indicator_count"] == 150
    assert health[0]["error_message"] is None
    assert health[0]["latency_ms"] == 250.5
    
    # Update with failure health info
    db.update_feed_health(
        feed_name="Abuse.ch URLhaus",
        status="FAILED",
        count=0,
        error_msg="Connection Timeout",
        latency_ms=5000.0
    )
    
    health = db.get_feed_health()
    assert len(health) == 1  # Replaced because feed_name is PRIMARY KEY
    assert health[0]["status"] == "FAILED"
    assert health[0]["error_message"] == "Connection Timeout"
    assert health[0]["indicator_count"] == 0

def test_sqlite_db_no_seeding_when_not_empty(test_db_path):
    # Create database and populate manually with 2 entries
    db = ThreatDB(test_db_path)
    db.add_iocs_batch([
        ("custom1.com", "Malware Host", 90.0, "real_feed", "Real threat intel"),
        ("custom2.com", "Phishing", 95.0, "real_feed", "Real threat intel")
    ])
    
    # Initialize the store which checks if database is empty to seed it
    store = IOCStore(db_path=test_db_path)
    
    # Check that count remains exactly 2 (no synthetic data was seeded)
    assert store.total_iocs() == 2
    assert store.lookup("custom1.com").matched is True
    assert store.lookup("synth-command-node-1.com").matched is False

from threat_intel.stix_parser import STIXParser

def test_stix_parser_valid_bundle():
    valid_stix = """
    {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "created": "2026-08-20T12:00:00.000Z",
                "created_by_ref": "feed-a",
                "name": "Malicious Command & Control",
                "description": "Known malware C2 domain detected",
                "indicator_types": ["malicious-activity", "c2"],
                "pattern": "[domain-name:value = 'bad-c2-stix.com']",
                "pattern_type": "stix",
                "confidence": 95
            }
        ]
    }
    """
    iocs = STIXParser.parse_stix_json(valid_stix)
    assert len(iocs) == 1
    ioc = iocs[0]
    assert ioc["domain"] == "bad-c2-stix.com"
    assert ioc["category"] == "Command & Control (C2)"
    assert ioc["confidence"] == 95.0
    assert ioc["source"] == "feed-a"
    assert ioc["details"] == "Known malware C2 domain detected"
    assert ioc["timestamp"] == "2026-08-20T12:00:00.000Z"

def test_stix_parser_multiple_indicators():
    valid_stix = """
    {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'domain1.com']",
                "indicator_types": ["phishing"],
                "confidence": 90
            },
            {
                "type": "indicator",
                "pattern": "[domain-name:value IN ('domain2.net', 'domain3.org')]",
                "indicator_types": ["malicious-activity"],
                "confidence": 75
            }
        ]
    }
    """
    iocs = STIXParser.parse_stix_json(valid_stix)
    assert len(iocs) == 3
    domains = [ioc["domain"] for ioc in iocs]
    assert "domain1.com" in domains
    assert "domain2.net" in domains
    assert "domain3.org" in domains
    
    phish_ioc = next(ioc for ioc in iocs if ioc["domain"] == "domain1.com")
    assert phish_ioc["category"] == "Phishing"

def test_stix_parser_normalization():
    stix = """
    {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'https://EVIL-STIX.net:8443/']",
                "confidence": 85
            }
        ]
    }
    """
    iocs = STIXParser.parse_stix_json(stix)
    assert len(iocs) == 1
    assert iocs[0]["domain"] == "evil-stix.net"

def test_stix_parser_unsupported_types():
    stix = """
    {
        "type": "bundle",
        "objects": [
            {
                "type": "threat-actor",
                "name": "Actor A"
            },
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '192.168.1.100']"
            },
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'good-domain.com']",
                "confidence": 70
            }
        ]
    }
    """
    iocs = STIXParser.parse_stix_json(stix)
    assert len(iocs) == 1
    assert iocs[0]["domain"] == "good-domain.com"

def test_stix_parser_malformed_input():
    assert STIXParser.parse_stix_json("invalid json string{") == []
    assert STIXParser.parse_stix_json("") == []
    assert STIXParser.parse_stix_json(None) == []

def test_stix_parser_duplicate_indicators():
    stix = """
    {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'dup-domain.com']",
                "confidence": 70
            },
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'dup-domain.com']",
                "confidence": 92
            }
        ]
    }
    """
    iocs = STIXParser.parse_stix_json(stix)
    assert len(iocs) == 1
    assert iocs[0]["domain"] == "dup-domain.com"
    assert iocs[0]["confidence"] == 92.0

from threat_intel.aggregator import ThreatAggregator, resolve_category

def test_category_priority_resolution():
    # command and control priority over malware/phishing
    assert resolve_category("Phishing", "Command & Control (C2)") == "Command & Control (C2)"
    assert resolve_category("Command & Control (C2)", "Phishing") == "Command & Control (C2)"
    assert resolve_category("Botnet", "Malware Host") == "Botnet"
    assert resolve_category("Malware Host", "Phishing") == "Malware Host"
    assert resolve_category("Phishing", "Malicious Domain") == "Phishing"

def test_aggregator_multi_source_and_attribution(test_db_path):
    store = IOCStore(db_path=test_db_path)
    aggregator = ThreatAggregator(store)
    
    # Setup mock feed inputs with conflicting details/categories/domains
    feeds_data = {
        "AlienVault OTX": [
            {
                "domain": "EVIL-TARGET.com",
                "category": "Phishing",
                "confidence": 70.0,
                "details": "Phishing credential theft landing page"
            },
            {
                "domain": "phish-bank.org",
                "category": "Phishing",
                "confidence": 85.0,
                "details": "Bank phishing page"
            }
        ],
        "Abuse.ch URLhaus": [
            {
                "domain": "evil-target.com.",
                "category": "Command & Control (C2)",
                "confidence": 95.0,
                "details": "C2 Server node for Trojan malware"
            },
            {
                "domain": "malware-download.xyz",
                "category": "Malware Host",
                "confidence": 60.0,
                "details": "Payload downloader"
            }
        ]
    }
    
    aggregated = aggregator.aggregate_feeds(feeds_data)
    
    # 3 unique domains normalized and aggregated
    assert len(aggregated) == 3
    
    # Verify details for evil-target.com (should resolve to C2 server, max confidence 95, attribution AlienVault OTX, Abuse.ch URLhaus)
    evil_target = next(item for item in aggregated if item[0] == "evil-target.com")
    assert evil_target[1] == "Command & Control (C2)" # Priority resolved from Phishing -> C2
    assert evil_target[2] == 95.0                     # Max confidence 95.0
    assert evil_target[3] == "Abuse.ch URLhaus, AlienVault OTX"  # Source attribution joined alphabetically
    assert evil_target[4] == "C2 Server node for Trojan malware" # Higher-confidence description kept

def test_aggregator_empty_and_malformed_feeds(test_db_path):
    store = IOCStore(db_path=test_db_path)
    aggregator = ThreatAggregator(store)
    
    feeds_data = {
        "Empty Feed": [],
        "Malformed Feed": [
            {"domain": "", "category": "Malware Host", "confidence": 90.0},
            {"domain": "good-domain.com", "category": "Phishing", "confidence": None} # None evaluates to 80.0 fallback
        ]
    }
    
    aggregated = aggregator.aggregate_feeds(feeds_data)
    
    # "good-domain.com" should be aggregated, malformed/empty skipped
    assert len(aggregated) == 1
    assert aggregated[0][0] == "good-domain.com"
    assert aggregated[0][2] == 80.0 # Fallback confidence

def test_aggregator_store_sync_and_health(test_db_path):
    # Initialize with clean db (no seeding, we populate via aggregator)
    db = ThreatDB(test_db_path)
    db.add_iocs_batch([("initial.com", "Malware Host", 90.0, "real", "real IOC")])
    store = IOCStore(db_path=test_db_path)
    
    assert store.total_iocs() == 1
    
    aggregator = ThreatAggregator(store)
    
    # Aggregated indicators to write
    aggregated_iocs = [
        ("evil-node.net", "Botnet", 92.5, "Feed A", "C2 Node"),
        ("phish-target.com", "Phishing", 88.0, "Feed B", "Fake portal")
    ]
    
    # Health status metadata
    feed_statuses = {
        "Feed A": {
            "status": "SUCCESS",
            "count": 1,
            "error_message": None,
            "latency_ms": 120.4
        },
        "Feed B": {
            "status": "FAILED",
            "count": 0,
            "error_message": "HTTP 500 Server Error",
            "latency_ms": 3200.0
        }
    }
    
    # Trigger update
    aggregator.update_store_and_db(aggregated_iocs, feed_statuses)
    
    # 1. Verify in-memory store is synchronized (now has 3 items: initial.com + 2 new ones)
    assert store.total_iocs() == 3
    assert store.lookup("evil-node.net").matched is True
    assert store.lookup("phish-target.com").matched is True
    
    # 2. Verify health statistics are stored
    health = db.get_feed_health()
    assert len(health) == 2
    
    feed_a_health = next(h for h in health if h["feed_name"] == "Feed A")
    assert feed_a_health["status"] == "SUCCESS"
    assert feed_a_health["indicator_count"] == 1
    assert feed_a_health["latency_ms"] == 120.4
    
    feed_b_health = next(h for h in health if h["feed_name"] == "Feed B")
    assert feed_b_health["status"] == "FAILED"
    assert feed_b_health["error_message"] == "HTTP 500 Server Error"
    assert feed_b_health["latency_ms"] == 3200.0



