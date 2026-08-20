import socket
from typing import Optional
from shared.schemas import SecurityDecision

try:
    import dns.message
    import dns.rdatatype
    import dns.rdataclass
    import dns.rrset
    import dns.rcode
    import dns.flags
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class ActionHandler:
    """
    Synthetic DNS wire response generator for blocked and failed queries.
    Constructs instant sinkhole (0.0.0.0 / ::), NXDOMAIN, and SERVFAIL binary responses
    without performing external network calls.
    Owned by Member 2 (Resolver Lead).
    """

    @classmethod
    def handle_block(
        cls,
        raw_query: bytes,
        decision: Optional[SecurityDecision] = None,
        mode: str = "SINKHOLE",
        sinkhole_ip: str = "0.0.0.0",
        ttl: int = 300,
    ) -> Optional[bytes]:
        """
        Primary handler for BLOCK security decisions.
        Generates synthetic sinkhole or NXDOMAIN DNS wire response.
        """
        if not raw_query or len(raw_query) < 12:
            return None

        clean_mode = (mode or "SINKHOLE").strip().upper()
        if clean_mode == "NXDOMAIN":
            return cls.create_nxdomain_response(raw_query)
        else:
            return cls.create_sinkhole_response(raw_query, sinkhole_ip=sinkhole_ip, ttl=ttl)

    @classmethod
    def create_sinkhole_response(
        cls,
        raw_query: bytes,
        sinkhole_ip: str = "0.0.0.0",
        sinkhole_ipv6: str = "::",
        ttl: int = 300,
    ) -> Optional[bytes]:
        """
        Constructs a synthetic DNS response containing a sinkhole IP address (0.0.0.0 or ::).
        Preserves transaction ID and original question.
        """
        if not raw_query or len(raw_query) < 12:
            return None

        if HAS_DNSPYTHON:
            try:
                query_msg = dns.message.from_wire(raw_query)
                response_msg = dns.message.make_response(query_msg)
                response_msg.flags |= dns.flags.AA
                response_msg.flags |= dns.flags.RA

                if query_msg.question:
                    q = query_msg.question[0]
                    if q.rdtype == dns.rdatatype.A:
                        rrset = dns.rrset.from_text(
                            q.name,
                            ttl,
                            dns.rdataclass.IN,
                            dns.rdatatype.A,
                            sinkhole_ip,
                        )
                        response_msg.answer.append(rrset)
                    elif q.rdtype == dns.rdatatype.AAAA:
                        rrset = dns.rrset.from_text(
                            q.name,
                            ttl,
                            dns.rdataclass.IN,
                            dns.rdatatype.AAAA,
                            sinkhole_ipv6,
                        )
                        response_msg.answer.append(rrset)
                    # For other QTYPEs (TXT, MX, etc.), answer section remains empty (NODATA NOERROR)

                return response_msg.to_wire()
            except (dns.exception.DNSException, ValueError, IndexError, KeyError):
                return None
        else:
            # Fallback zero-dependency manual binary builder
            return cls._build_manual_response(
                raw_query,
                rcode=0,
                sinkhole_ip=sinkhole_ip,
                ttl=ttl,
            )

    @classmethod
    def create_nxdomain_response(cls, raw_query: bytes) -> Optional[bytes]:
        """
        Constructs a synthetic NXDOMAIN (RCODE 3 - Non-Existent Domain) response.
        """
        if not raw_query or len(raw_query) < 12:
            return None

        if HAS_DNSPYTHON:
            try:
                query_msg = dns.message.from_wire(raw_query)
                response_msg = dns.message.make_response(query_msg)
                response_msg.set_rcode(dns.rcode.NXDOMAIN)
                response_msg.flags |= dns.flags.AA
                response_msg.flags |= dns.flags.RA
                return response_msg.to_wire()
            except (dns.exception.DNSException, ValueError, IndexError, KeyError):
                return None
        else:
            return cls._build_manual_response(raw_query, rcode=3)

    @classmethod
    def create_servfail_response(cls, raw_query: bytes) -> Optional[bytes]:
        """
        Constructs a synthetic SERVFAIL (RCODE 2 - Server Failure) response.
        Used when upstream DNS resolvers are unreachable.
        """
        if not raw_query or len(raw_query) < 12:
            return None

        if HAS_DNSPYTHON:
            try:
                query_msg = dns.message.from_wire(raw_query)
                response_msg = dns.message.make_response(query_msg)
                response_msg.set_rcode(dns.rcode.SERVFAIL)
                response_msg.flags |= dns.flags.RA
                return response_msg.to_wire()
            except (dns.exception.DNSException, ValueError, IndexError, KeyError):
                return None
        else:
            return cls._build_manual_response(raw_query, rcode=2)

    @classmethod
    def _build_manual_response(
        cls,
        raw_query: bytes,
        rcode: int = 0,
        sinkhole_ip: Optional[str] = None,
        ttl: int = 300,
    ) -> Optional[bytes]:
        """
        Manual RFC 1035 binary wire response builder fallback.
        """
        try:
            if len(raw_query) < 12:
                return None

            # Extract 2-byte transaction ID
            tx_id = raw_query[0:2]

            # Flags: QR=1 (response), RD=copied from query, RA=1, AA=1, RCODE=rcode
            rd_flag = raw_query[2] & 0x01
            flag_byte1 = 0x84 | rd_flag  # QR=1 (0x80) | AA=1 (0x04) | RD
            flag_byte2 = 0x80 | (rcode & 0x0F)  # RA=1 (0x80) | RCODE

            # Parse question section length to preserve question
            idx = 12
            while idx < len(raw_query):
                length = raw_query[idx]
                if length == 0:
                    idx += 5  # Null byte (1) + QTYPE (2) + QCLASS (2)
                    break
                idx += 1 + length

            if idx > len(raw_query):
                return None

            question_bytes = raw_query[12:idx]
            qtype = int.from_bytes(question_bytes[-4:-2], byteorder="big") if len(question_bytes) >= 4 else 1

            include_answer = (rcode == 0 and sinkhole_ip is not None and qtype == 1)  # QTYPE A = 1
            ancount = 1 if include_answer else 0

            # 12-byte header: ID (2), Flags (2), QDCOUNT=1 (2), ANCOUNT (2), NSCOUNT=0 (2), ARCOUNT=0 (2)
            header = bytearray(tx_id)
            header.extend(bytes([flag_byte1, flag_byte2]))
            header.extend(b"\x00\x01")  # QDCOUNT = 1
            header.extend(ancount.to_bytes(2, byteorder="big"))  # ANCOUNT
            header.extend(b"\x00\x00\x00\x00")  # NSCOUNT=0, ARCOUNT=0

            response = header + question_bytes

            if include_answer:
                # Answer Section: Name pointer (0xc00c) -> Type A (1) -> Class IN (1) -> TTL -> RDLENGTH (4) -> IP
                ip_parts = [int(p) for p in sinkhole_ip.split(".")]
                if len(ip_parts) == 4:
                    answer_record = bytearray(b"\xc0\x0c")  # Compression pointer to offset 12 (question domain)
                    answer_record.extend(b"\x00\x01\x00\x01")  # Type A, Class IN
                    answer_record.extend(ttl.to_bytes(4, byteorder="big"))  # TTL
                    answer_record.extend(b"\x00\x04")  # RDLENGTH = 4
                    answer_record.extend(bytes(ip_parts))  # 4-byte IPv4 address
                    response += answer_record

            return bytes(response)
        except Exception:
            return None
