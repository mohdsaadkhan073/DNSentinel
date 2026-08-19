import os
import socket
from typing import Optional

try:
    import dns.message
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from shared.config import UPSTREAM_DNS_PRIMARY, UPSTREAM_DNS_SECONDARY

DEFAULT_DNS_TIMEOUT: float = float(os.getenv("DNS_TIMEOUT_SECONDS", "2.0"))
DEFAULT_DNS_PORT: int = 53
BUFFER_SIZE: int = 4096


class UpstreamDNSClient:
    """
    High-performance upstream DNS client with primary and secondary failover.
    Forwards raw wire-format DNS packets and provides direct domain resolution.
    Owned by Member 2 (Resolver Lead).
    """

    def __init__(
        self,
        primary_upstream: str = UPSTREAM_DNS_PRIMARY,
        secondary_upstream: str = UPSTREAM_DNS_SECONDARY,
        port: int = DEFAULT_DNS_PORT,
        default_timeout: float = DEFAULT_DNS_TIMEOUT,
    ):
        self.primary_upstream = primary_upstream
        self.secondary_upstream = secondary_upstream
        self.port = port
        self.default_timeout = default_timeout

    def _send_udp_query(
        self,
        server_ip: str,
        raw_query: bytes,
        timeout: float,
    ) -> Optional[bytes]:
        """
        Sends raw DNS query bytes to target DNS server via UDP socket.
        """
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(raw_query, (server_ip, self.port))
            response_data, _ = sock.recvfrom(BUFFER_SIZE)
            return response_data
        except (socket.timeout, TimeoutError):
            return None
        except OSError:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def forward_query(
        self,
        raw_query: bytes,
        timeout: Optional[float] = None,
    ) -> Optional[bytes]:
        """
        Forwards raw DNS wire packet to primary upstream with automatic failover to secondary.
        Preserves raw wire format, transaction IDs, and flags unchanged.
        """
        t = timeout if timeout is not None else self.default_timeout

        # Attempt 1: Primary Upstream
        if self.primary_upstream:
            response = self._send_udp_query(self.primary_upstream, raw_query, t)
            if response is not None:
                return response

        # Attempt 2: Secondary Upstream Fallback
        if self.secondary_upstream and self.secondary_upstream != self.primary_upstream:
            response = self._send_udp_query(self.secondary_upstream, raw_query, t)
            if response is not None:
                return response

        return None

    def resolve_domain(
        self,
        domain: str,
        qtype: str = "A",
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """
        Helper method to resolve domain name into a string value (e.g. IP address)
        using dnspython wire parser when available, or raw wire builder fallback.
        """
        clean_domain = domain.strip().rstrip(".")
        if not clean_domain:
            return None

        if HAS_DNSPYTHON:
            try:
                qtype_enum = dns.rdatatype.from_text(qtype)
                query_msg = dns.message.make_query(clean_domain, qtype_enum)
                raw_query = query_msg.to_wire()

                raw_response = self.forward_query(raw_query, timeout=timeout)
                if not raw_response:
                    return None

                response_msg = dns.message.from_wire(raw_response)
                for section in (response_msg.answer, response_msg.additional):
                    for rrset in section:
                        if rrset.rdtype == qtype_enum and len(rrset) > 0:
                            return str(rrset[0])

                return None
            except (dns.exception.DNSException, ValueError, IndexError, KeyError):
                return None
        else:
            # Zero-dependency raw wire packet builder for standard A-record queries
            try:
                # 12-byte header: ID (2B), Flags=0x0100 (RD=1) (2B), QDCOUNT=1 (2B), ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
                packet = bytearray(b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                for label in clean_domain.split("."):
                    encoded_label = label.encode("ascii", errors="ignore")
                    packet.append(len(encoded_label))
                    packet.extend(encoded_label)
                packet.append(0)  # Null terminator for domain name
                packet.extend(b"\x00\x01\x00\x01")  # QTYPE = A (1), QCLASS = IN (1)

                raw_response = self.forward_query(bytes(packet), timeout=timeout)
                if not raw_response or len(raw_response) < 16:
                    return None

                # Extract last 4 bytes as IPv4 address if response contains valid answer
                # Basic check: ANCOUNT > 0 (bytes 6-7)
                ancount = int.from_bytes(raw_response[6:8], byteorder="big")
                if ancount > 0 and len(raw_response) >= 16:
                    # In standard A record answer, IP is typically the last 4 bytes of the RDATA
                    ip_bytes = raw_response[-4:]
                    return ".".join(str(b) for b in ip_bytes)

                return None
            except Exception:
                return None

    def resolve(
        self,
        domain: str,
        qtype: str = "A",
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """
        Backward-compatible alias for resolve_domain.
        """
        return self.resolve_domain(domain=domain, qtype=qtype, timeout=timeout)
