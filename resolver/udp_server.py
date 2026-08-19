import socket
import asyncio
import uuid
from typing import Optional, Tuple

try:
    import dns.message
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from shared.schemas import DNSQuery, ProtocolType, ActionDecision
from shared.config import DNS_UDP_PORT
from resolver.upstream_client import UpstreamDNSClient
from resolver.action_handler import ActionHandler

BUFFER_SIZE: int = 4096


class UDPResolverServer:
    """
    Production-ready DNS over UDP Server (Port 53) Listener.
    Decodes incoming raw DNS queries, delegates decisions to Orchestrator,
    and returns synthetic or upstream-forwarded binary responses.
    Owned by Member 2 (Resolver Lead).
    """

    def __init__(
        self,
        orchestrator=None,
        upstream_client: Optional[UpstreamDNSClient] = None,
        action_handler=ActionHandler,
        host: str = "0.0.0.0",
        port: int = DNS_UDP_PORT,
    ):
        self.orchestrator = orchestrator
        self.upstream_client = upstream_client or UpstreamDNSClient()
        self.action_handler = action_handler or ActionHandler
        self.host = host
        self.port = port
        self.running = False
        self._sock: Optional[socket.socket] = None

    def decode_dns_query(self, data: bytes, addr: Tuple[str, int]) -> Optional[DNSQuery]:
        """
        Parses raw UDP DNS query packet payload into a DNSQuery schema object.
        Returns None if packet is malformed or truncated.
        """
        if not data or len(data) < 12:
            return None

        if HAS_DNSPYTHON:
            try:
                msg = dns.message.from_wire(data)
                if not msg.question:
                    return None
                q = msg.question[0]
                domain = str(q.name).strip().rstrip(".")
                if not domain:
                    return None
                qtype_str = dns.rdatatype.to_text(q.rdtype)
                return DNSQuery(
                    query_id=f"tx-{msg.id:04x}",
                    domain=domain,
                    client_ip=addr[0],
                    protocol=ProtocolType.UDP,
                    qtype=qtype_str,
                )
            except (dns.exception.DNSException, ValueError, IndexError, KeyError):
                return None
        else:
            # Minimal byte parsing fallback
            try:
                tx_id = int.from_bytes(data[0:2], byteorder="big")
                idx = 12
                parts = []
                while idx < len(data):
                    length = data[idx]
                    if length == 0:
                        idx += 1
                        break
                    idx += 1
                    parts.append(data[idx:idx + length].decode("ascii", errors="ignore"))
                    idx += length

                if not parts or idx + 4 > len(data):
                    return None

                domain = ".".join(parts).strip().rstrip(".")
                if not domain:
                    return None

                qtype_int = int.from_bytes(data[idx:idx + 2], byteorder="big")
                qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 12: "PTR"}
                qtype_str = qtype_map.get(qtype_int, "A")

                return DNSQuery(
                    query_id=f"tx-{tx_id:04x}",
                    domain=domain,
                    client_ip=addr[0],
                    protocol=ProtocolType.UDP,
                    qtype=qtype_str,
                )
            except Exception:
                return None

    def handle_packet(
        self,
        data: bytes,
        addr: Tuple[str, int],
        sock: Optional[socket.socket] = None,
    ) -> Optional[bytes]:
        """
        Processes a single incoming UDP DNS datagram:
        1. Decodes query into DNSQuery
        2. Routes to Orchestrator for Threat Intel / Risk Engine evaluation
        3. Generates synthetic response (on BLOCK) or forwards to upstream (on ALLOW/SUSPICIOUS)
        4. Transmits response back to client socket
        """
        query = self.decode_dns_query(data, addr)
        if query is None:
            # Malformed query: safely drop without server crash
            return None

        response: Optional[bytes] = None

        if self.orchestrator:
            try:
                decision = self.orchestrator.process_query(query)
                if decision.action == ActionDecision.BLOCK:
                    # BLOCK: Return synthetic 0.0.0.0 sinkhole response
                    response = self.action_handler.handle_block(
                        raw_query=data,
                        decision=decision,
                        mode="SINKHOLE",
                    )
                else:
                    # ALLOW or SUSPICIOUS: Forward to upstream DNS resolvers
                    response = self.upstream_client.forward_query(data)
                    if response is None:
                        # Upstream total failure: Return synthetic SERVFAIL
                        response = self.action_handler.create_servfail_response(data)
            except Exception:
                # Orchestrator failure recovery: Return SERVFAIL
                response = self.action_handler.create_servfail_response(data)
        else:
            # Standalone mode without orchestrator: Direct upstream forward
            response = self.upstream_client.forward_query(data)
            if response is None:
                response = self.action_handler.create_servfail_response(data)

        # Transmit response back to client if socket provided and response available
        if sock and response:
            try:
                sock.sendto(response, addr)
            except OSError:
                pass

        return response

    def _recv_with_timeout(self) -> Tuple[Optional[bytes], Optional[Tuple[str, int]]]:
        """
        Helper for receiving datagram with socket timeout.
        """
        if not self._sock:
            return None, None
        try:
            self._sock.settimeout(0.5)
            data, addr = self._sock.recvfrom(BUFFER_SIZE)
            return data, addr
        except (socket.timeout, TimeoutError):
            return None, None
        except OSError:
            return None, None

    async def start(self):
        """
        Starts the asynchronous UDP DNS listening loop on configured host and port.
        """
        self.running = True
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            print(f"[Resolver] UDP DNS Server listening on {self.host}:{self.port}...")
        except Exception as e:
            self.running = False
            if self._sock:
                self._sock.close()
                self._sock = None
            raise OSError(f"Failed to bind UDP DNS Server on {self.host}:{self.port}: {e}")

        loop = asyncio.get_running_loop()
        try:
            while self.running:
                data, addr = await loop.run_in_executor(None, self._recv_with_timeout)
                if not data or not addr or not self.running:
                    continue
                self.handle_packet(data, addr, self._sock)
        except asyncio.CancelledError:
            pass
        finally:
            self.stop()

    def stop(self):
        """
        Gracefully stops the server and closes the underlying UDP socket.
        """
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        print(f"[Resolver] UDP DNS Server on port {self.port} stopped.")
