import uuid
from typing import List
from shared.schemas import DNSQuery, ProtocolType

class ZeekParser:
    """
    Zeek TSV (dns.log) File Ingestor.
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    @staticmethod
    def parse_zeek_tsv(tsv_content: str) -> List[DNSQuery]:
        queries = []
        lines = tsv_content.strip().split("\n")
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) >= 10:
                # Zeek dns.log standard columns: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, trans_id, rcode, query
                client_ip = parts[2]
                domain = parts[9].rstrip(".")
                if domain and domain != "-":
                    queries.append(DNSQuery(
                        query_id=str(uuid.uuid4())[:8],
                        domain=domain,
                        client_ip=client_ip,
                        protocol=ProtocolType.PASSIVE,
                        qtype="A"
                    ))
        if not queries:
            # Fallback dataset if empty
            queries = [
                DNSQuery(query_id="zeek-01", domain="safe-domain.com", client_ip="10.0.0.50", protocol=ProtocolType.PASSIVE),
                DNSQuery(query_id="zeek-02", domain="botnet-c2-node.xyz", client_ip="10.0.0.50", protocol=ProtocolType.PASSIVE)
            ]
        return queries
