"""PCAP/Zeek upload processing.

Mocked today -- Member 5 owns the real passive analyzer. The upload route
saves the file and this returns a plausible forensic summary shaped like
the eventual real response, so the frontend never has to change.
"""

import random


def mock_pcap_result(filename: str) -> dict:
    total_packets = random.randint(8000, 25000)
    dns_queries = int(total_packets * random.uniform(0.1, 0.18))
    malicious = int(dns_queries * random.uniform(0.02, 0.05))
    suspicious = int(dns_queries * random.uniform(0.04, 0.08))
    dga = int(malicious * random.uniform(0.3, 0.5))
    tunneling = int(malicious * random.uniform(0.15, 0.3))
    blocked = malicious + int(suspicious * 0.2)

    return {
        "filename": filename,
        "status": "completed",
        "total_packets": total_packets,
        "dns_queries": dns_queries,
        "malicious_domains": malicious,
        "suspicious_domains": suspicious,
        "dga_detected": dga,
        "tunneling_detected": tunneling,
        "blocked": blocked,
    }
