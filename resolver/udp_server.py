import socket
import asyncio
import uuid
from shared.schemas import DNSQuery, ProtocolType
from shared.config import DNS_UDP_PORT

class UDPResolverServer:
    """
    DNS over UDP Server (Port 53) Listener.
    Owned by Member 2 (Resolver Lead).
    """

    def __init__(self, orchestrator=None, port: int = DNS_UDP_PORT):
        self.orchestrator = orchestrator
        self.port = port
        self.running = False

    def decode_dns_query(self, data: bytes, addr: tuple) -> DNSQuery:
        """
        Parses raw UDP DNS query packet payload.
        """
        domain = "example.com"
        try:
            if len(data) > 12:
                # Basic domain extraction skeleton
                parts = []
                idx = 12
                while idx < len(data):
                    length = data[idx]
                    if length == 0:
                        break
                    idx += 1
                    parts.append(data[idx:idx+length].decode('utf-8', errors='ignore'))
                    idx += length
                if parts:
                    domain = ".".join(parts)
        except Exception:
            pass

        return DNSQuery(
            query_id=str(uuid.uuid4())[:8],
            domain=domain,
            client_ip=addr[0],
            protocol=ProtocolType.UDP,
            qtype="A"
        )

    async def start(self):
        self.running = True
        print(f"[Resolver] UDP DNS Server starting on port {self.port}...")
        # Server loop placeholder
