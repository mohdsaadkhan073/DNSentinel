import time
from typing import Optional

try:
    import dns.message
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from shared.schemas import DNSQuery, ProtocolType, ActionDecision
from resolver.upstream_client import UpstreamDNSClient
from resolver.action_handler import ActionHandler
from resolver.metrics import ResolverMetrics, resolver_metrics


class DTLSServer:
    """
    DNS over DTLS (RFC 8094) Application-Layer Processing Engine.

    NOTE ON DTLS TRANSPORT READINESS:
    - This module implements the complete RFC 8094 application-layer DNS processing pipeline
      (decoding decrypted DNS payloads, tagging as ProtocolType.DTLS, Orchestrator evaluation,
       BLOCK/ALLOW/SERVFAIL routing, and resolver metrics instrumentation).
    - CPython standard library 'ssl' does not support UDP DTLS sockets (SOCK_DGRAM),
      and no native DTLS library (e.g. pyOpenSSL/pydtls) or server certificates are currently
      configured in this runtime.
    - Therefore, `dtls_transport_ready` is False. Plaintext DNS is STRICTLY NOT bound to Port 853.
      This engine awaits a dedicated DTLS transport adapter when native bindings are deployed.

    Owned by Member 2 (Resolver Lead).
    """

    def __init__(
        self,
        orchestrator=None,
        upstream_client: Optional[UpstreamDNSClient] = None,
        action_handler=ActionHandler,
        metrics: Optional[ResolverMetrics] = None,
        port: int = 853,
    ):
        self.orchestrator = orchestrator
        self.upstream_client = upstream_client or UpstreamDNSClient()
        self.action_handler = action_handler or ActionHandler
        self.metrics = metrics or resolver_metrics
        self.port = port
        self.running = False

    @property
    def dtls_transport_ready(self) -> bool:
        """
        Indicates whether native DTLS transport encryption is available.
        Currently False due to missing Python UDP DTLS socket bindings and certificates.
        """
        return False

    def decode_dns_query(self, raw_dns: bytes, client_ip: str = "127.0.0.1") -> Optional[DNSQuery]:
        """
        Parses decrypted DNS wire bytes into a DNSQuery schema object tagged with ProtocolType.DTLS.
        """
        if not raw_dns or len(raw_dns) < 12:
            return None

        if HAS_DNSPYTHON:
            try:
                msg = dns.message.from_wire(raw_dns)
                if not msg.question:
                    return None
                q = msg.question[0]
                domain = str(q.name).strip().rstrip(".")
                if not domain:
                    return None
                qtype_str = dns.rdatatype.to_text(q.rdtype)
                return DNSQuery(
                    query_id=f"dtls-{msg.id:04x}",
                    domain=domain,
                    client_ip=client_ip,
                    protocol=ProtocolType.DTLS,
                    qtype=qtype_str,
                )
            except (dns.exception.DNSException, ValueError, IndexError, KeyError):
                return None
        else:
            try:
                tx_id = int.from_bytes(raw_dns[0:2], byteorder="big")
                idx = 12
                parts = []
                while idx < len(raw_dns):
                    length = raw_dns[idx]
                    if length == 0:
                        idx += 1
                        break
                    idx += 1
                    parts.append(raw_dns[idx:idx + length].decode("ascii", errors="ignore"))
                    idx += length

                if not parts or idx + 4 > len(raw_dns):
                    return None

                domain = ".".join(parts).strip().rstrip(".")
                if not domain:
                    return None

                qtype_int = int.from_bytes(raw_dns[idx:idx + 2], byteorder="big")
                qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 12: "PTR"}
                qtype_str = qtype_map.get(qtype_int, "A")

                return DNSQuery(
                    query_id=f"dtls-{tx_id:04x}",
                    domain=domain,
                    client_ip=client_ip,
                    protocol=ProtocolType.DTLS,
                    qtype=qtype_str,
                )
            except Exception:
                return None

    def process_decrypted_dns_payload(
        self,
        raw_dns: bytes,
        client_ip: str = "127.0.0.1",
    ) -> Optional[bytes]:
        """
        Processes a decrypted DNS wire payload according to RFC 8094 rules:
        1. Decodes query and tags with ProtocolType.DTLS
        2. Routes to Orchestrator for Threat Intel / Risk Engine evaluation
        3. Routes to ActionHandler (BLOCK -> 0.0.0.0) or UpstreamClient (ALLOW/SUSPICIOUS)
        4. Instruments ResolverMetrics with ProtocolType.DTLS
        5. Returns unencrypted DNS response bytes ready for DTLS transport encryption
        """
        start_time = time.perf_counter()
        query = self.decode_dns_query(raw_dns, client_ip)
        if query is None:
            return None

        response: Optional[bytes] = None
        action_decision = ActionDecision.ALLOW
        cache_hit = False
        upstream_failed = False

        if self.orchestrator:
            try:
                decision = self.orchestrator.process_query(query)
                action_decision = decision.action
                cache_hit = decision.cache_hit

                if decision.action == ActionDecision.BLOCK:
                    response = self.action_handler.handle_block(
                        raw_query=raw_dns,
                        decision=decision,
                        mode="SINKHOLE",
                    )
                else:
                    # ALLOW or SUSPICIOUS
                    response = self.upstream_client.forward_query(raw_dns)
                    if response is None:
                        upstream_failed = True
                        response = self.action_handler.create_servfail_response(raw_dns)
            except Exception:
                upstream_failed = True
                response = self.action_handler.create_servfail_response(raw_dns)
        else:
            # Standalone fallback without orchestrator
            response = self.upstream_client.forward_query(raw_dns)
            if response is None:
                upstream_failed = True
                response = self.action_handler.create_servfail_response(raw_dns)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if self.metrics:
            self.metrics.record_query(
                protocol=ProtocolType.DTLS,
                action=action_decision,
                latency_ms=elapsed_ms,
                cache_hit=cache_hit,
                upstream_failed=upstream_failed,
            )

        return response

    def handle_dtls_datagram(self, raw_data: bytes, client_ip: str = "127.0.0.1") -> Optional[DNSQuery]:
        """
        Legacy skeleton compatibility method.
        """
        return self.decode_dns_query(raw_data, client_ip)

    async def start(self):
        """
        Lifecycle start hook.
        Strictly refuses to bind a plaintext UDP socket to Port 853 under the guise of DTLS.
        """
        raise NotImplementedError(
            "DTLS transport encryption is currently blocked. "
            "Python standard library 'ssl' lacks UDP DTLS support, and native DTLS bindings/certificates "
            "are not configured. Plaintext UDP is strictly forbidden on Port 853."
        )

    def stop(self):
        """
        Lifecycle stop hook.
        """
        self.running = False
