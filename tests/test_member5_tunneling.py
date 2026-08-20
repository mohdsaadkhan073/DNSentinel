import pytest
import time
from datetime import datetime
from shared.schemas import DNSQuery, ProtocolType, TunnelResult, ActionDecision
from passive.volume_tracker import VolumeTracker
from passive.tunnel_detector import TunnelDetector
from passive.pcap_parser import PCAPParser
from passive.zeek_parser import ZeekParser
from passive.batch_analyzer import BatchAnalyzer


def test_entropy_calculation():
    # Low entropy (repeating characters)
    low_h = TunnelDetector.calculate_entropy("aaaaaaa")
    assert low_h == 0.0

    # High entropy (random base64/hex characters)
    high_h = TunnelDetector.calculate_entropy("4f8a91b2c3d4e5f6")
    assert high_h > 3.5


def test_subdomain_prefix_extraction():
    prefix1 = TunnelDetector.extract_subdomain_prefix("a1b2c3d4.attacker.com")
    assert prefix1 == "a1b2c3d4"

    prefix2 = TunnelDetector.extract_subdomain_prefix("example.com")
    assert prefix2 == "example"


def test_tunnel_detector_clean_query():
    detector = TunnelDetector()
    query = DNSQuery(
        query_id="t-01",
        domain="google.com",
        client_ip="192.168.1.50",
        protocol=ProtocolType.UDP,
        qtype="A"
    )
    result = detector.analyze(query)
    assert isinstance(result, TunnelResult)
    assert result.is_tunnel is False
    assert result.tunnel_score < 40.0


def test_tunnel_detector_high_entropy_and_prefix_length():
    detector = TunnelDetector()
    # High entropy + long prefix (>30 chars) + TXT record
    query = DNSQuery(
        query_id="t-02",
        domain="4f8a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8.exfiltrate.net",
        client_ip="192.168.1.55",
        protocol=ProtocolType.UDP,
        qtype="TXT"
    )
    result = detector.analyze(query)
    assert result.is_tunnel is True
    assert result.tunnel_score >= 60.0
    assert "High subdomain entropy" in result.reason or "Excessive subdomain prefix length" in result.reason


def test_volume_tracker_sliding_window():
    tracker = VolumeTracker(window_seconds=2)
    ip = "10.0.0.1"

    # Record 5 queries
    for i in range(5):
        tracker.record_query(ip, f"sub{i}.domain.com", "A")

    count, total_bytes = tracker.get_stats(ip)
    assert count == 5
    assert total_bytes > 0

    # Wait for window to expire
    time.sleep(2.1)
    count_after, bytes_after = tracker.get_stats(ip)
    assert count_after == 0
    assert bytes_after == 0


def test_tunnel_detector_rate_burst():
    tracker = VolumeTracker(window_seconds=60)
    detector = TunnelDetector(volume_tracker=tracker)
    ip = "192.168.1.99"

    # Simulate 52 rapid queries with long subdomain exfiltration payload
    for i in range(52):
        q = DNSQuery(
            query_id=f"burst-{i}",
            domain=f"data-chunk-exfiltration-encoded-payload-{i}.exfil-server.com",
            client_ip=ip,
            protocol=ProtocolType.UDP,
            qtype="TXT"
        )
        res = detector.analyze(q)

    assert res.is_tunnel is True
    assert res.tunnel_score >= 60.0
    assert "Exfiltration volume burst" in res.reason


def test_zeek_parser_tsv():
    tsv_content = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rcode	query	qtype_name
1629456000.100	C123	10.0.0.88	5353	8.8.8.8	53	udp	101	0	normal-query.org	A
1629456001.200	C124	10.0.0.88	5354	8.8.8.8	53	udp	102	0	a1b2c3d4e5f6789.tunnel-exfil.biz	TXT
"""
    queries = ZeekParser.parse_zeek_tsv(tsv_content)
    assert len(queries) == 2
    assert queries[0].domain == "normal-query.org"
    assert queries[0].client_ip == "10.0.0.88"
    assert queries[1].qtype == "TXT"


def test_pcap_parser_fallback():
    # Parsing empty or invalid bytes falls back to mock dataset gracefully
    queries = PCAPParser.parse_pcap(b"")
    assert len(queries) > 0
    assert queries[0].protocol == ProtocolType.PASSIVE


def test_batch_analyzer_payload_calculation():
    analyzer = BatchAnalyzer()
    queries = [
        DNSQuery(query_id="b1", domain="example.com", client_ip="192.168.1.1", protocol=ProtocolType.PASSIVE),
        DNSQuery(query_id="b2", domain="subdomain.bad-c2-server.org", client_ip="192.168.1.2", protocol=ProtocolType.PASSIVE, qtype="TXT")
    ]
    report = analyzer.analyze_batch(queries)
    assert report["total_queries"] == 2
    assert report["total_payload_bytes"] > 0
    assert "estimated_payload_mb" in report
    assert len(report["decisions"]) == 2
