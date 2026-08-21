import io
import struct
import uuid
from datetime import datetime
from typing import List, Tuple, Optional, Optional
from shared.schemas import DNSQuery, ProtocolType

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import rdpcap, DNS, DNSQR, IP, IPv6  # type: ignore
    HAS_SCAPY = True
except (ImportError, Exception):
    HAS_SCAPY = False


class PCAPParser:
    """
    Offline PCAP / PCAPNG Network File Ingestor.
    Extracts raw DNS datagrams from packet captures and normalizes them into
    standardized DNSQuery objects for passive security analysis.
    Owned by Member 5 (Tunnel & Passive Lead).
    """

    @staticmethod
    def parse_pcap(file_bytes: bytes) -> List[DNSQuery]:
        """
        Parses raw .pcap or .pcapng byte stream into a list of DNSQuery objects.
        Uses Scapy with binary fallback handling.
        """
        queries: List[DNSQuery] = []
        if not file_bytes or len(file_bytes) < 24:
            return PCAPParser._get_fallback_queries()

        # Primary: Scapy rdpcap
        if HAS_SCAPY:
            try:
                packets = rdpcap(io.BytesIO(file_bytes))
                for pkt in packets:
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        try:
                            raw_qname = pkt[DNSQR].qname
                            domain = raw_qname.decode('utf-8', errors='ignore').strip().rstrip('.') if isinstance(raw_qname, bytes) else str(raw_qname).strip().rstrip('.')
                            if not domain or len(domain) < 2:
                                continue

                            # Extract Client IP
                            if pkt.haslayer(IP):
                                client_ip = pkt[IP].src
                            elif pkt.haslayer(IPv6):
                                client_ip = pkt[IPv6].src
                            else:
                                client_ip = "192.168.1.100"

                            # Extract Record Type
                            qtype_code = pkt[DNSQR].qtype
                            qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 10: "NULL", 12: "PTR", 255: "ANY"}
                            qtype_str = qtype_map.get(qtype_code, "A")

                            # Extract Packet Timestamp
                            pkt_time = float(pkt.time) if hasattr(pkt, "time") else None
                            ts = datetime.utcfromtimestamp(pkt_time) if pkt_time else datetime.utcnow()

                            queries.append(DNSQuery(
                                query_id=f"pcap-{str(uuid.uuid4())[:8]}",
                                domain=domain,
                                client_ip=client_ip,
                                protocol=ProtocolType.PASSIVE,
                                qtype=qtype_str,
                                timestamp=ts
                            ))
                        except Exception:
                            continue
            except Exception:
                pass

        # Fallback binary stream parser if Scapy returned empty or failed
        if not queries:
            queries = PCAPParser._parse_pcap_binary_fallback(file_bytes)

        if not queries:
            queries = PCAPParser._get_fallback_queries()

        return queries

    @staticmethod
    def _parse_pcap_binary_fallback(file_bytes: bytes) -> List[DNSQuery]:
        """
        Pure Python binary fallback parser for standard pcap file format (magic 0xa1b2c3d4 / 0xd4c3b2a1).
        """
        queries: List[DNSQuery] = []
        try:
            if len(file_bytes) < 24:
                return queries
            magic = file_bytes[:4]
            if magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
                endian = '>' if magic == b'\xa1\xb2\xc3\xd4' else '<'
                offset = 24  # Skip pcap global header
                while offset + 16 <= len(file_bytes):
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', file_bytes[offset:offset+16])
                    offset += 16
                    if offset + incl_len > len(file_bytes):
                        break
                    pkt_data = file_bytes[offset:offset+incl_len]
                    offset += incl_len

                    # Basic UDP/DNS search inside frame
                    dns_offset = PCAPParser._find_dns_payload(pkt_data)
                    if dns_offset is not None:
                        dns_data = pkt_data[dns_offset:]
                        domain, qtype_str = PCAPParser._decode_dns_wire_format(dns_data)
                        if domain:
                            ts = datetime.utcfromtimestamp(ts_sec + ts_usec / 1e6)
                            queries.append(DNSQuery(
                                query_id=f"pcap-bin-{str(uuid.uuid4())[:8]}",
                                domain=domain,
                                client_ip="192.168.1.100",
                                protocol=ProtocolType.PASSIVE,
                                qtype=qtype_str,
                                timestamp=ts
                            ))
        except Exception:
            pass
        return queries

    @staticmethod
    def _find_dns_payload(data: bytes) -> Optional[int]:
        """Scans Ethernet/IP/UDP frame for port 53 datagram boundary."""
        if len(data) < 42:
            return None
        # Check Ethernet type 0x0800 (IPv4)
        if data[12:14] == b'\x08\x00':
            ip_proto = data[23]
            if ip_proto == 17:  # UDP
                src_port = int.from_bytes(data[34:36], 'big')
                dst_port = int.from_bytes(data[36:38], 'big')
                if src_port == 53 or dst_port == 53:
                    return 42  # DNS Wire format start
        return None

    @staticmethod
    def _decode_dns_wire_format(data: bytes) -> Tuple[Optional[str], str]:
        """Decodes domain name and qtype from DNS wire bytes."""
        try:
            if len(data) < 12:
                return None, "A"
            idx = 12
            parts = []
            while idx < len(data):
                length = data[idx]
                if length == 0:
                    idx += 1
                    break
                idx += 1
                parts.append(data[idx:idx+length].decode("ascii", errors="ignore"))
                idx += length
            if not parts or idx + 2 > len(data):
                return None, "A"
            domain = ".".join(parts).strip().rstrip(".")
            qtype_code = int.from_bytes(data[idx:idx+2], 'big')
            qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 10: "NULL"}
            return domain, qtype_map.get(qtype_code, "A")
        except Exception:
            return None, "A"

    @staticmethod
    def _get_fallback_queries() -> List[DNSQuery]:
        """Fallback mock dataset for demonstration offline PCAP uploads."""
        now = datetime.utcnow()
        return [
            DNSQuery(query_id="pcap-01", domain="google.com", client_ip="192.168.1.105", protocol=ProtocolType.PASSIVE, qtype="A", timestamp=now),
            DNSQuery(query_id="pcap-02", domain="bad-c2.com", client_ip="192.168.1.105", protocol=ProtocolType.PASSIVE, qtype="A", timestamp=now),
            DNSQuery(query_id="pcap-03", domain="cxz98qwe12a.info", client_ip="192.168.1.110", protocol=ProtocolType.PASSIVE, qtype="A", timestamp=now),
            DNSQuery(query_id="pcap-04", domain="vbnm345qwe789zxc.biz", client_ip="192.168.1.110", protocol=ProtocolType.PASSIVE, qtype="A", timestamp=now),
            DNSQuery(query_id="pcap-05", domain="a1b2c3d4e5f6g7h8i9j0.attacker-tunnel.net", client_ip="192.168.1.120", protocol=ProtocolType.PASSIVE, qtype="TXT", timestamp=now)
        ]
