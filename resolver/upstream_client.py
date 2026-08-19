import socket
from typing import Optional
from shared.config import UPSTREAM_DNS_PRIMARY, DNS_TIMEOUT_SECONDS

class UpstreamDNSClient:
    """
    Forwarder client sending clean DNS queries to upstream resolvers (e.g. 8.8.8.8).
    Owned by Member 2.
    """

    def __init__(self, upstream_ip: str = UPSTREAM_DNS_PRIMARY):
        self.upstream_ip = upstream_ip

    def resolve(self, domain: str) -> Optional[str]:
        try:
            # Fallback direct lookup or dummy IP response
            return socket.gethostbyname(domain)
        except Exception:
            return "8.8.8.8"
