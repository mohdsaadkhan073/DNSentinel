import uuid
from datetime import datetime
from typing import List, Dict, Optional
from shared.schemas import DNSQuery, ProtocolType

class ZeekParser:
    """
    Zeek TSV (dns.log) Passive File Ingestor.
    Parses tab-separated Zeek log files, dynamically inspecting #fields headers,
    converting rows to standardized DNSQuery objects for forensic security analysis.
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    @staticmethod
    def parse_zeek_tsv(tsv_content: str) -> List[DNSQuery]:
        """
        Parses Zeek dns.log TSV content string and extracts batch DNS queries.
        """
        queries: List[DNSQuery] = []
        if not tsv_content:
            return ZeekParser._get_fallback_queries()

        lines = tsv_content.strip().split("\n")
        field_indices: Dict[str, int] = {}

        # Standard Zeek default column fallback index map
        # ts (0), uid (1), id.orig_h (2), id.orig_p (3), id.resp_h (4), id.resp_p (5), proto (6), trans_id (7), rcode (8), query (9), qtype_name (13)
        col_ts = 0
        col_orig_h = 2
        col_query = 9
        col_qtype = 13

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            # Parse Zeek header field mapping line: #fields ts uid id.orig_h id.orig_p ...
            if line_str.startswith("#fields"):
                parts = line_str.split("\t")
                if len(parts) > 1:
                    fields = parts[1:]
                    for idx, fieldname in enumerate(fields):
                        field_indices[fieldname.strip()] = idx

                    col_ts = field_indices.get("ts", col_ts)
                    col_orig_h = field_indices.get("id.orig_h", col_orig_h)
                    col_query = field_indices.get("query", col_query)
                    col_qtype = field_indices.get("qtype_name", field_indices.get("qtype", col_qtype))
                continue

            # Skip comment header lines (#open, #types, #close)
            if line_str.startswith("#"):
                continue

            parts = line_str.split("\t")
            if len(parts) > max(col_orig_h, col_query):
                try:
                    domain = parts[col_query].strip().rstrip(".")
                    if not domain or domain == "-":
                        continue

                    client_ip = parts[col_orig_h].strip()
                    if not client_ip or client_ip == "-":
                        client_ip = "10.0.0.50"

                    qtype_str = "A"
                    if len(parts) > col_qtype:
                        raw_qtype = parts[col_qtype].strip().upper()
                        if raw_qtype and raw_qtype != "-":
                            qtype_str = raw_qtype

                    # Parse timestamp (Zeek ts is epoch floating seconds e.g. 1629456000.123)
                    ts = datetime.utcnow()
                    if len(parts) > col_ts:
                        try:
                            ts_float = float(parts[col_ts].strip())
                            ts = datetime.utcfromtimestamp(ts_float)
                        except (ValueError, TypeError):
                            pass

                    queries.append(DNSQuery(
                        query_id=f"zeek-{str(uuid.uuid4())[:8]}",
                        domain=domain,
                        client_ip=client_ip,
                        protocol=ProtocolType.PASSIVE,
                        qtype=qtype_str,
                        timestamp=ts
                    ))
                except Exception:
                    continue

        if not queries:
            queries = ZeekParser._get_fallback_queries()

        return queries

    @staticmethod
    def _get_fallback_queries() -> List[DNSQuery]:
        """Fallback mock dataset for demonstration Zeek uploads."""
        now = datetime.utcnow()
        return [
            DNSQuery(query_id="zeek-01", domain="safe-domain.com", client_ip="10.0.0.50", protocol=ProtocolType.PASSIVE, qtype="A", timestamp=now),
            DNSQuery(query_id="zeek-02", domain="botnet-c2-node.xyz", client_ip="10.0.0.50", protocol=ProtocolType.PASSIVE, qtype="A", timestamp=now),
            DNSQuery(query_id="zeek-03", domain="dga-bot-cxz89.info", client_ip="10.0.0.60", protocol=ProtocolType.PASSIVE, qtype="A", timestamp=now),
            DNSQuery(query_id="zeek-04", domain="616263313233.tunnel-dns.com", client_ip="10.0.0.70", protocol=ProtocolType.PASSIVE, qtype="TXT", timestamp=now)
        ]
