import os
import time
import requests
import sqlite3
import threading
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
    
    # Verify startup load time is well under 500ms for 50,000 records
    assert load_time_ms < 500.0
    
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

from unittest.mock import patch, MagicMock
from threat_intel.taxii_client import TAXIIClient

def test_taxii_client_init():
    # 1. TAXII client initialization
    client = TAXIIClient(
        server_url="https://test-taxii.org",
        api_root_path="custom-root",
        collection_id="coll-123",
        username="admin",
        password="password123",
        timeout=15
    )
    assert client.server_url == "https://test-taxii.org"
    assert client.api_root_path == "/custom-root"
    assert client.collection_id == "coll-123"
    assert client.auth == ("admin", "password123")
    assert client.timeout == 15

@patch("requests.get")
def test_taxii_client_discovery(mock_get):
    # 2. server/API discovery
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"api_roots": ["https://test-taxii.org/stix/"]}
    mock_get.return_value = mock_response
    
    client = TAXIIClient(server_url="https://test-taxii.org")
    roots = client.discover_api_roots()
    
    assert roots == ["https://test-taxii.org/stix/"]
    mock_get.assert_called_once_with(
        "https://test-taxii.org/taxii2/", 
        headers=client.headers, 
        auth=None, 
        timeout=10
    )

@patch("requests.get")
def test_taxii_client_get_collections(mock_get):
    # 3. collection discovery
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "collections": [
            {"id": "coll-1", "title": "Collection 1"},
            {"id": "coll-2", "title": "Collection 2"}
        ]
    }
    mock_get.return_value = mock_response
    
    client = TAXIIClient()
    collections = client.get_collections("https://test-taxii.org/stix/")
    
    assert len(collections) == 2
    assert collections[0]["id"] == "coll-1"
    assert collections[1]["title"] == "Collection 2"

@patch("requests.get")
def test_taxii_client_fetch_objects(mock_get):
    # 4. successful object retrieval
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'bad-c2.com']",
                "confidence": 90
            }
        ]
    }
    mock_get.return_value = mock_response
    
    client = TAXIIClient()
    bundle = client.fetch_collection_objects("https://test-taxii.org/stix/", "coll-123")
    
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 1
    assert "bad-c2.com" in bundle["objects"][0]["pattern"]

@patch("requests.get")
def test_taxii_client_pagination(mock_get):
    # 5. pagination
    def mock_get_side_effect(url, params=None, headers=None, auth=None, timeout=None):
        range_header = headers.get("Range", "")
        response = MagicMock()
        response.status_code = 200
        
        if "items 0-99" in range_header:
            response.json.return_value = {
                "type": "bundle",
                "objects": [{"type": "indicator", "pattern": f"[domain-name:value = 'domain-{i}.com']"} for i in range(100)]
            }
        elif "items 100-199" in range_header:
            response.json.return_value = {
                "type": "bundle",
                "objects": [{"type": "indicator", "pattern": f"[domain-name:value = 'domain-{i}.com']"} for i in range(100, 105)]
            }
        else:
            response.json.return_value = {"type": "bundle", "objects": []}
            
        return response

    mock_get.side_effect = mock_get_side_effect
    client = TAXIIClient(collection_id="coll-pagination")
    
    parsed, status = client.poll_and_parse_feed()
    
    assert status["status"] == "SUCCESS"
    assert status["count"] == 105
    assert len(parsed) == 105
    assert parsed[0]["domain"] == "domain-0.com"
    assert parsed[104]["domain"] == "domain-104.com"
    assert mock_get.call_count == 2

@patch("requests.get")
def test_taxii_client_auth_failure(mock_get):
    # 6. authentication failure
    mock_response = MagicMock()
    mock_response.status_code = 401
    http_error = requests.exceptions.HTTPError("Unauthorized", response=mock_response)
    mock_get.side_effect = http_error
    
    client = TAXIIClient()
    with pytest.raises(PermissionError):
        client.discover_api_roots()

@patch("requests.get")
def test_taxii_client_connection_failure(mock_get):
    # 7. connection failure
    mock_get.side_effect = requests.exceptions.ConnectionError("Network Down")
    
    client = TAXIIClient()
    with pytest.raises(ConnectionError):
        client.discover_api_roots()

@patch("requests.get")
def test_taxii_client_timeout(mock_get):
    # 8. timeout
    mock_get.side_effect = requests.exceptions.Timeout("Request Timeout")
    
    client = TAXIIClient()
    with pytest.raises(ConnectionError):
        client.discover_api_roots()

@patch("requests.get")
def test_taxii_client_malformed_response(mock_get):
    # 9. malformed response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_get.return_value = mock_response
    
    client = TAXIIClient(collection_id="coll-malformed")
    parsed, status = client.poll_and_parse_feed()
    
    assert status["status"] == "FAILED"
    assert "Invalid JSON" in status["error_message"]
    assert parsed == []

@patch("requests.get")
def test_taxii_client_empty_feed(mock_get):
    # 10. empty feed
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"type": "bundle", "objects": []}
    mock_get.return_value = mock_response
    
    client = TAXIIClient(collection_id="coll-empty")
    parsed, status = client.poll_and_parse_feed()
    
    assert status["status"] == "SUCCESS"
    assert status["count"] == 0
    assert parsed == []

@patch("requests.get")
def test_taxii_client_successful_update_and_integration(mock_get, test_db_path):
    # 11, 12, 13, 14, 15: update handling, duplicate handling, parser/aggregator integration & health logging
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "name": "C2 Server",
                "description": "TAXII feed threat",
                "indicator_types": ["c2-activity"],
                "pattern": "[domain-name:value = 'taxii-malicious.org']",
                "confidence": 88
            },
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'taxii-malicious.org']",
                "confidence": 70
            }
        ]
    }
    mock_get.return_value = mock_response
    
    store = IOCStore(db_path=test_db_path)
    aggregator = ThreatAggregator(store)
    client = TAXIIClient(collection_id="coll-test-update")
    
    parsed_indicators, status_info = client.poll_and_parse_feed()
    
    assert len(parsed_indicators) == 1
    assert parsed_indicators[0]["domain"] == "taxii-malicious.org"
    assert parsed_indicators[0]["confidence"] == 88.0
    assert parsed_indicators[0]["category"] == "Command & Control (C2)"
    
    aggregated = aggregator.aggregate_feeds({"TAXII Feed": parsed_indicators})
    feed_statuses = {"TAXII Feed": status_info}
    aggregator.update_store_and_db(aggregated, feed_statuses)
    
    assert store.lookup("taxii-malicious.org").matched is True
    assert store.lookup("taxii-malicious.org").intel_score == 88.0
    
    health = store.db.get_feed_health()
    assert len(health) == 1
    assert health[0]["feed_name"] == "TAXII Feed"
    assert health[0]["status"] == "SUCCESS"
    assert health[0]["indicator_count"] == 1

from threat_intel.background_worker import BackgroundWorker

def test_feed_health_advanced_tracking(test_db_path):
    db = ThreatDB(test_db_path)
    
    # 1. Initial State
    assert len(db.get_feed_health()) == 0
    
    # 2. First Success Update
    db.update_feed_health("Feed A", "SUCCESS", 50, latency_ms=100.0)
    health = db.get_feed_health()[0]
    assert health["consecutive_failures"] == 0
    assert health["last_sync"] is not None
    assert health["last_attempt"] is not None
    
    first_sync_time = health["last_sync"]
    
    # 3. Failed Update
    db.update_feed_health("Feed A", "FAILED", 0, error_msg="Timeout Error")
    health = db.get_feed_health()[0]
    assert health["consecutive_failures"] == 1
    assert health["last_sync"] == first_sync_time  # Retained old last_sync (no stale timestamp overwrite)
    assert health["error_message"] == "Timeout Error"
    
    # 4. Another Failure (consecutive failure tracking)
    db.update_feed_health("Feed A", "FAILED", 0, error_msg="HTTP 500")
    health = db.get_feed_health()[0]
    assert health["consecutive_failures"] == 2
    assert health["last_sync"] == first_sync_time
    
    # 5. Success resets failures
    time.sleep(1.0)
    db.update_feed_health("Feed A", "SUCCESS", 60)
    health = db.get_feed_health()[0]
    assert health["consecutive_failures"] == 0
    assert health["last_sync"] != first_sync_time  # Updated to new timestamp

def test_atomic_update_rollback_on_failure(test_db_path):
    store = IOCStore(db_path=test_db_path)
    # Clear store to be precise
    store._store = {"keep-me.com": {"category": "Botnet", "confidence": 99.0, "source": "local", "details": "local"}}
    store.db.add_iocs_batch([("keep-me.com", "Botnet", 99.0, "local", "local")])
    
    aggregator = ThreatAggregator(store)
    
    # Mock database to throw error on batch insert
    with patch.object(store.db, "add_iocs_batch", side_effect=sqlite3.Error("Disk full")):
        aggregated = [("new-malicious.com", "Phishing", 80.0, "Feed", "details")]
        feed_statuses = {"Feed A": {"status": "SUCCESS", "count": 1}}
        
        # Verify transaction failure throws error
        with pytest.raises(RuntimeError):
            aggregator.update_store_and_db(aggregated, feed_statuses)
            
        # Verify in-memory cache was NOT modified (atomic swap rollback)
        assert store.total_iocs() == 1
        assert store.lookup("keep-me.com").matched is True
        assert store.lookup("new-malicious.com").matched is False
        
        # Verify health status still logged feed failure
        health = store.db.get_feed_health()[0]
        assert health["status"] == "FAILED"
        assert "Atomic update failed" in health["error_message"]

def test_background_worker_flow(test_db_path):
    # Setup mocks for TAXIIClient
    mock_client1 = MagicMock()
    mock_client1.collection_id = "feed1-id-string"
    mock_client1.poll_and_parse_feed.return_value = (
        [{"domain": "c2-server.net", "category": "Command & Control (C2)", "confidence": 95.0, "source": "TAXII: feed1-id"}],
        {"status": "SUCCESS", "count": 1, "latency_ms": 50.0}
    )
    
    store = IOCStore(db_path=test_db_path)
    aggregator = ThreatAggregator(store)
    
    worker = BackgroundWorker(
        aggregator=aggregator,
        taxii_clients={"Feed 1": mock_client1},
        interval_seconds=0.2
    )
    
    assert worker._is_running is False
    
    # 1. Startup Worker
    worker.start()
    assert worker._is_running is True
    assert worker.is_alive() is True
    
    # Let worker execute at least once
    time.sleep(0.3)
    
    # 2. Shutdown Worker
    worker.stop()
    assert worker._is_running is False
    assert worker.is_alive() is False
    
    # Verify records written and memory sync'd
    assert store.lookup("c2-server.net").matched is True
    
    health = store.db.get_feed_health()[0]
    assert health["feed_name"] == "Feed 1"
    assert health["status"] == "SUCCESS"
    assert health["indicator_count"] == 1

def test_background_worker_overlapping_prevention(test_db_path):
    mock_client = MagicMock()
    # Mock poll to sleep so we can check concurrency lock behavior
    def slow_poll():
        time.sleep(0.5)
        return [], {"status": "SUCCESS", "count": 0}
        
    mock_client.poll_and_parse_feed.side_effect = slow_poll
    
    store = IOCStore(db_path=test_db_path)
    aggregator = ThreatAggregator(store)
    worker = BackgroundWorker(aggregator, {"Slow Feed": mock_client}, interval_seconds=10.0)
    
    # Run sync in background thread
    t = threading.Thread(target=worker.sync_all_feeds)
    t.start()
    
    time.sleep(0.1) # Wait for thread to acquire lock
    
    # Try calling concurrently while lock is active
    statuses = worker.sync_all_feeds()
    
    # Overlapping execution should yield empty statuses (skipped run)
    assert statuses == {}
    
    t.join()

def test_multiple_feeds_one_fails_one_succeeds(test_db_path):
    # Feed 1 Succeeds
    mock_client1 = MagicMock()
    mock_client1.collection_id = "feed1-id-string"
    mock_client1.poll_and_parse_feed.return_value = (
        [{"domain": "good-intel.com", "category": "Phishing", "confidence": 90.0, "source": "TAXII: feed1-id"}],
        {"status": "SUCCESS", "count": 1, "latency_ms": 20.0}
    )
    
    # Feed 2 Fails
    mock_client2 = MagicMock()
    mock_client2.collection_id = "feed2-id-string"
    mock_client2.poll_and_parse_feed.return_value = (
        [],
        {"status": "FAILED", "count": 0, "error_message": "Timeout Connecting", "latency_ms": 3000.0}
    )
    
    store = IOCStore(db_path=test_db_path)
    aggregator = ThreatAggregator(store)
    worker = BackgroundWorker(aggregator, {"Feed 1": mock_client1, "Feed 2": mock_client2}, interval_seconds=10.0)
    
    statuses = worker.sync_all_feeds()
    
    # Verify overall execution didn't crash
    assert len(statuses) == 2
    assert statuses["Feed 1"]["status"] == "SUCCESS"
    assert statuses["Feed 2"]["status"] == "FAILED"
    
    # Verify Feed 1 data loaded, old valid cache remains
    assert store.lookup("good-intel.com").matched is True
    
    # Verify health status logging matches
    health = store.db.get_feed_health()
    f1_health = next(h for h in health if h["feed_name"] == "Feed 1")
    assert f1_health["status"] == "SUCCESS"
    
    f2_health = next(h for h in health if h["feed_name"] == "Feed 2")
    assert f2_health["status"] == "FAILED"
    assert f2_health["error_message"] == "Timeout Connecting"
    assert f2_health["consecutive_failures"] == 1

def test_orchestrator_initialization_and_lookup(test_db_path):
    from core.orchestrator import Orchestrator
    from shared.schemas import DNSQuery, ActionDecision
    
    # 1. Initialize store & orchestrator
    store = IOCStore(db_path=test_db_path)
    orchestrator = Orchestrator(ioc_store=store)
    
    # 2. Test malicious domain query (exact match)
    query_malicious = DNSQuery(query_id="q-malicious", domain="bad-c2.com", client_ip="192.168.1.5")
    decision = orchestrator.process_query(query_malicious)
    
    assert decision.intel_result.matched is True
    assert decision.action == ActionDecision.BLOCK
    assert decision.intel_result.threat_category == "Command & Control (C2)"
    assert decision.intel_result.intel_score == 100.0
    assert decision.intel_result.source_feed == "demo_seed"
    
    # 3. Test clean domain query (no match)
    query_clean = DNSQuery(query_id="q-clean", domain="google.com", client_ip="192.168.1.5")
    decision_clean = orchestrator.process_query(query_clean)
    
    assert decision_clean.intel_result.matched is False
    assert decision_clean.action == ActionDecision.ALLOW
    assert decision_clean.intel_result.intel_score == 0.0

def test_orchestrator_normalization_and_subdomains(test_db_path):
    from core.orchestrator import Orchestrator
    from shared.schemas import DNSQuery, ActionDecision
    
    store = IOCStore(db_path=test_db_path)
    orchestrator = Orchestrator(ioc_store=store)
    
    # 1. Normalization check: EVIL-tracker.info. with spaces and uppercase
    query_norm = DNSQuery(query_id="q-norm", domain="  HTTPS://EVIL-TRACKER.INFO.  ", client_ip="192.168.1.5")
    decision = orchestrator.process_query(query_norm)
    assert decision.intel_result.matched is True
    assert decision.action == ActionDecision.BLOCK
    
    # 2. Subdomain check: child.botnet-c2-node.xyz
    query_sub = DNSQuery(query_id="q-sub", domain="child.botnet-c2-node.xyz", client_ip="192.168.1.5")
    decision_sub = orchestrator.process_query(query_sub)
    assert decision_sub.intel_result.matched is True
    assert decision_sub.action == ActionDecision.BLOCK

def test_orchestrator_with_background_worker_active(test_db_path):
    from core.orchestrator import Orchestrator
    from shared.schemas import DNSQuery
    
    mock_client = MagicMock()
    mock_client.collection_id = "feed-id"
    mock_client.poll_and_parse_feed.return_value = (
        [{"domain": "background-bad.org", "category": "Botnet", "confidence": 95.0, "source": "TAXII: feed-id"}],
        {"status": "SUCCESS", "count": 1, "latency_ms": 10.0}
    )
    
    store = IOCStore(db_path=test_db_path)
    aggregator = ThreatAggregator(store)
    worker = BackgroundWorker(aggregator, {"TAXII": mock_client}, interval_seconds=0.1)
    
    orchestrator = Orchestrator(ioc_store=store)
    
    worker.start()
    
    # System lookup paths remain live and functioning during thread update execution
    query_clean = DNSQuery(query_id="q-1", domain="google.com", client_ip="192.168.1.1")
    decision_clean = orchestrator.process_query(query_clean)
    assert decision_clean.intel_result.matched is False
    
    time.sleep(0.2)
    
    # Verify lookup registers the new parsed domain post-worker update loop
    query_new = DNSQuery(query_id="q-2", domain="background-bad.org", client_ip="192.168.1.1")
    decision_new = orchestrator.process_query(query_new)
    assert decision_new.intel_result.matched is True
    
    worker.stop()






