import os
import time
import socket
import select
import threading
import asyncio
from typing import Optional, Dict, Tuple

try:
    import OpenSSL.SSL as SSL
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False

try:
    import dns.message
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from shared.schemas import DNSQuery, ProtocolType, ActionDecision
from shared.config import DNS_DTLS_PORT, DTLS_CERT_PATH, DTLS_KEY_PATH
from resolver.upstream_client import UpstreamDNSClient
from resolver.action_handler import ActionHandler
from resolver.metrics import ResolverMetrics, resolver_metrics

# DTLS 1.2 protocol version constant for OpenSSL (0xFEFD)
DTLS1_2_VERSION_HEX = 0xFEFD


class DTLSSession:
    """
    Encapsulates state for a single client DTLS session identified by (ip, port).
    Uses an isolated Memory-BIO connection to manage DTLS 1.2 handshake and encryption.
    """

    def __init__(self, client_addr: Tuple[str, int], context: "SSL.Context"):
        self.client_addr = client_addr
        self.conn = SSL.Connection(context, None)
        self.conn.set_accept_state()
        self.handshake_complete = False
        self.last_seen = time.time()

    def bio_write(self, data: bytes):
        """Feeds incoming encrypted network datagram into the SSL memory BIO."""
        self.conn.bio_write(data)
        self.last_seen = time.time()

    def bio_read(self, bufsize: int = 4096) -> bytes:
        """Drains outgoing encrypted ciphertext from the SSL memory BIO."""
        out = []
        while True:
            try:
                chunk = self.conn.bio_read(bufsize)
                if chunk:
                    out.append(chunk)
                else:
                    break
            except SSL.WantReadError:
                break
            except Exception:
                break
        return b"".join(out)


class DTLSServer:
    """
    DNS over DTLS (RFC 8094) Server Implementation.
    Provides true encrypted DTLS 1.2 datagram transport over UDP using pyOpenSSL,
    with per-client session multiplexing and direct integration into the DNSentinel
    security pipeline (Orchestrator, ActionHandler, ResolverMetrics).

    Owned by Member 2 (Resolver Lead).
    """

    def __init__(
        self,
        orchestrator=None,
        upstream_client: Optional[UpstreamDNSClient] = None,
        action_handler=ActionHandler,
        metrics: Optional[ResolverMetrics] = None,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = DNS_DTLS_PORT,
    ):
        self.orchestrator = orchestrator
        self.upstream_client = upstream_client or UpstreamDNSClient()
        self.action_handler = action_handler or ActionHandler
        self.metrics = metrics or resolver_metrics
        self.cert_path = cert_path or DTLS_CERT_PATH
        self.key_path = key_path or DTLS_KEY_PATH
        self.host = host
        self.port = port

        self.running = False
        self.sock: Optional[socket.socket] = None
        self.ssl_context: Optional[SSL.Context] = None
        self.sessions: Dict[Tuple[str, int], DTLSSession] = {}
        self._lock = threading.Lock()

        # Telemetry counters
        self.handshakes_completed: int = 0
        self.handshakes_failed: int = 0

    @property
    def dtls_transport_ready(self) -> bool:
        """
        Returns True if pyOpenSSL is installed and valid certificate & key files exist.
        """
        if not HAS_PYOPENSSL:
            return False
        if not self.cert_path or not os.path.exists(self.cert_path):
            return False
        if not self.key_path or not os.path.exists(self.key_path):
            return False
        return True

    def _create_ssl_context(self) -> SSL.Context:
        """
        Initializes and returns a DTLS 1.2 server context with configured certificates.
        """
        if not HAS_PYOPENSSL:
            raise RuntimeError("pyOpenSSL is required for DTLS transport.")

        if not os.path.exists(self.cert_path):
            raise FileNotFoundError(f"DTLS certificate not found at: {self.cert_path}")
        if not os.path.exists(self.key_path):
            raise FileNotFoundError(f"DTLS private key not found at: {self.key_path}")

        ctx = SSL.Context(SSL.DTLS_SERVER_METHOD)

        # Enforce DTLS 1.2 minimum version
        try:
            ctx.set_min_proto_version(DTLS1_2_VERSION_HEX)
        except Exception:
            pass

        ctx.set_options(
            SSL.OP_NO_SSLv2
            | SSL.OP_NO_SSLv3
            | SSL.OP_NO_TLSv1
            | SSL.OP_NO_TLSv1_1
            | SSL.OP_NO_COMPRESSION
        )

        ctx.set_verify(SSL.VERIFY_NONE)
        ctx.use_certificate_file(self.cert_path, SSL.FILETYPE_PEM)
        ctx.use_privatekey_file(self.key_path, SSL.FILETYPE_PEM)
        ctx.check_privatekey()

        return ctx

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

    def _handle_incoming_datagram(self, data: bytes, addr: Tuple[str, int]):
        """
        Processes one incoming UDP datagram:
        - Rejects plaintext DNS datagrams
        - Feeds encrypted bytes into the matching client DTLS session
        - Advances handshake / decrypts application data
        - Transmits outgoing encrypted datagrams back to the client socket
        """
        if not data or len(data) < 13:
            # Truncated or empty datagram
            return

        # Plaintext Rejection Invariant:
        # DTLS records must have ContentType in (0x14, 0x15, 0x16, 0x17) and major version 0xFE
        content_type = data[0]
        major_ver = data[1]
        if content_type not in (20, 21, 22, 23) or major_ver != 0xFE:
            # Plaintext DNS packet or non-DTLS traffic -> drop immediately without response
            return

        with self._lock:
            session = self.sessions.get(addr)
            if session is None:
                if not self.ssl_context:
                    return
                session = DTLSSession(addr, self.ssl_context)
                self.sessions[addr] = session

        try:
            # 1. Feed incoming encrypted datagram into session memory BIO
            session.bio_write(data)

            # 2. Advance handshake if not yet established
            if not session.handshake_complete:
                try:
                    session.conn.do_handshake()
                    session.handshake_complete = True
                    self.handshakes_completed += 1
                except SSL.WantReadError:
                    pass
                except SSL.Error:
                    self.handshakes_failed += 1
                    with self._lock:
                        self.sessions.pop(addr, None)
                    return

                # Drain and send any handshake response records (ServerHello, Certificate, etc.)
                out_handshake = session.bio_read()
                if out_handshake and self.sock:
                    self.sock.sendto(out_handshake, addr)

            # 3. If handshake is complete, read decrypted application data
            if session.handshake_complete:
                while True:
                    try:
                        decrypted_dns = session.conn.recv(4096)
                        if not decrypted_dns:
                            break

                        # Process DNS query through security engine
                        dns_resp = self.process_decrypted_dns_payload(decrypted_dns, client_ip=addr[0])
                        if dns_resp:
                            session.conn.send(dns_resp)
                            out_resp = session.bio_read()
                            if out_resp and self.sock:
                                self.sock.sendto(out_resp, addr)
                    except SSL.WantReadError:
                        break
                    except SSL.ZeroReturnError:
                        # Clean session close
                        with self._lock:
                            self.sessions.pop(addr, None)
                        break
                    except SSL.Error:
                        break

        except Exception:
            with self._lock:
                self.sessions.pop(addr, None)

    def _clean_idle_sessions(self, timeout_seconds: float = 60.0):
        """Prunes inactive DTLS sessions to prevent memory leaks."""
        now = time.time()
        with self._lock:
            expired = [
                addr for addr, sess in self.sessions.items()
                if now - sess.last_seen > timeout_seconds
            ]
            for addr in expired:
                self.sessions.pop(addr, None)

    def _serve_loop(self):
        """Synchronous datagram listening loop."""
        self.ssl_context = self._create_ssl_context()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.setblocking(False)
        self.running = True

        last_clean = time.time()

        while self.running:
            try:
                r, _, _ = select.select([self.sock], [], [], 0.05)
                if r and self.sock:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        if data:
                            self._handle_incoming_datagram(data, addr)
                    except (BlockingIOError, socket.error):
                        pass

                if time.time() - last_clean > 10.0:
                    self._clean_idle_sessions()
                    last_clean = time.time()

            except Exception:
                if not self.running:
                    break

        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def start_sync(self):
        """Starts the DTLS server synchronously in a background thread."""
        thread = threading.Thread(target=self._serve_loop, daemon=True)
        thread.start()
        # Wait until socket is bound
        timeout = 2.0
        start = time.time()
        while not self.running and time.time() - start < timeout:
            time.sleep(0.02)

    async def start(self):
        """Asynchronous lifecycle start method."""
        if not self.dtls_transport_ready:
            raise RuntimeError(
                "DTLS transport cannot start: pyOpenSSL or certificate/key files are missing."
            )
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.start_sync)

    def stop(self):
        """Gracefully stops the DTLS server and cleans up resources."""
        self.running = False
        with self._lock:
            self.sessions.clear()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def handle_dtls_datagram(self, raw_data: bytes, client_ip: str = "127.0.0.1") -> Optional[DNSQuery]:
        """Legacy skeleton compatibility method."""
        return self.decode_dns_query(raw_data, client_ip)
