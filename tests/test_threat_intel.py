import pytest
from threat_intel.ioc_store import IOCStore, normalize_domain
from shared.schemas import ThreatIntelResult

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

def test_ioc_store_lookup_exact():
    store = IOCStore()
    
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

def test_ioc_store_lookup_parent():
    store = IOCStore()
    
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

def test_ioc_store_check_domain_alias():
    store = IOCStore()
    res = store.check_domain("bad-c2.com")
    assert res.matched is True

def test_ioc_store_add_ioc():
    store = IOCStore()
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
