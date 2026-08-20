import pytest
import time
from shared.schemas import DNSQuery, ProtocolType, ActionDecision, SecurityDecision, ThreatIntelResult, MLDgaResult, TunnelResult
from resolver.dns_cache import DNSCache
from resolver.upstream_client import UpstreamDNSClient
from resolver.action_handler import ActionHandler
from resolver.metrics import ResolverMetrics
from resolver.udp_server import UDPResolverServer

def test_dns_cache_hit_and_expiration():
    cache = DNSCache(default_ttl_seconds=0.2, max_entries=5)
    query = DNSQuery(query_id="cache-01", domain="test.com", client_ip="127.0.0.1")
    decision = SecurityDecision(
        decision_id="dec-01",
        query=query,
        action=ActionDecision.ALLOW,
        composite_risk_score=10.0,
        intel_result=ThreatIntelResult(),
        ml_result=MLDgaResult(),
        tunnel_result=TunnelResult(),
        latency_ms=2.5,
        rationale="Allowed"
    )

    cache.set("test.com", decision)
    hit = cache.get("test.com")
    assert hit is not None
    assert hit.query.domain == "test.com"
    assert cache.stats["hits"] == 1

    time.sleep(0.3)
    miss = cache.get("test.com")
    assert miss is None
    assert cache.stats["misses"] == 1

def test_action_handler_sinkhole():
    # 12-byte minimal query packet for "example.com"
    raw_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    response = ActionHandler.handle_block(raw_query, mode="SINKHOLE", sinkhole_ip="0.0.0.0")
    assert response is not None
    assert len(response) > len(raw_query)

def test_action_handler_nxdomain():
    raw_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    response = ActionHandler.handle_block(raw_query, mode="NXDOMAIN")
    assert response is not None
    assert len(response) >= 12

def test_resolver_metrics_record():
    metrics = ResolverMetrics()
    metrics.record_query(ProtocolType.UDP, ActionDecision.ALLOW, latency_ms=10.5, cache_hit=False)
    metrics.record_query(ProtocolType.UDP, ActionDecision.BLOCK, latency_ms=2.0, cache_hit=False)
    metrics.record_query(ProtocolType.UDP, ActionDecision.ALLOW, latency_ms=1.5, cache_hit=True)

    summary = metrics.summary()
    assert summary["total_queries"] == 3
    assert summary["blocked_queries"] == 1
    assert summary["cache_hits"] == 1

def test_udp_server_query_decoding():
    raw_query = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
    server = UDPResolverServer()
    decoded = server.decode_dns_query(raw_query, ("192.168.1.10", 53535))
    assert decoded is not None
    assert decoded.domain == "google.com"
    assert decoded.client_ip == "192.168.1.10"
