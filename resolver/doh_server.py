import base64
import time
import asyncio
from typing import Optional

try:
    import dns.message
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from fastapi import FastAPI, APIRouter, Request, Response, HTTPException, Query, status
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from shared.schemas import DNSQuery, ProtocolType, ActionDecision
from resolver.upstream_client import UpstreamDNSClient
from resolver.action_handler import ActionHandler
from resolver.metrics import ResolverMetrics, resolver_metrics

DOH_MEDIA_TYPE = "application/dns-message"


class DoHServer:
    """
    DNS over HTTPS (RFC 8484) Server implementation.
    Handles HTTP GET (base64url) and POST (raw wire body) DNS queries,
    integrating with Orchestrator, ActionHandler, and ResolverMetrics.
    Owned by Member 2 (Resolver Lead).
    """

    def __init__(
        self,
        orchestrator=None,
        upstream_client: Optional[UpstreamDNSClient] = None,
        action_handler=ActionHandler,
        metrics: Optional[ResolverMetrics] = None,
    ):
        self.orchestrator = orchestrator
        self.upstream_client = upstream_client or UpstreamDNSClient()
        self.action_handler = action_handler or ActionHandler
        self.metrics = metrics or resolver_metrics

    def decode_dns_query(self, raw_query: bytes, client_ip: str = "127.0.0.1") -> Optional[DNSQuery]:
        """
        Decodes raw DNS wire bytes into a DNSQuery schema object with ProtocolType.DOH.
        """
        if not raw_query or len(raw_query) < 12:
            return None

        if HAS_DNSPYTHON:
            try:
                msg = dns.message.from_wire(raw_query)
                if not msg.question:
                    return None
                q = msg.question[0]
                domain = str(q.name).strip().rstrip(".")
                if not domain:
                    return None
                qtype_str = dns.rdatatype.to_text(q.rdtype)
                return DNSQuery(
                    query_id=f"doh-{msg.id:04x}",
                    domain=domain,
                    client_ip=client_ip,
                    protocol=ProtocolType.DOH,
                    qtype=qtype_str,
                )
            except (dns.exception.DNSException, ValueError, IndexError, KeyError):
                return None
        else:
            try:
                tx_id = int.from_bytes(raw_query[0:2], byteorder="big")
                idx = 12
                parts = []
                while idx < len(raw_query):
                    length = raw_query[idx]
                    if length == 0:
                        idx += 1
                        break
                    idx += 1
                    parts.append(raw_query[idx:idx + length].decode("ascii", errors="ignore"))
                    idx += length

                if not parts or idx + 4 > len(raw_query):
                    return None

                domain = ".".join(parts).strip().rstrip(".")
                if not domain:
                    return None

                qtype_int = int.from_bytes(raw_query[idx:idx + 2], byteorder="big")
                qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 12: "PTR"}
                qtype_str = qtype_map.get(qtype_int, "A")

                return DNSQuery(
                    query_id=f"doh-{tx_id:04x}",
                    domain=domain,
                    client_ip=client_ip,
                    protocol=ProtocolType.DOH,
                    qtype=qtype_str,
                )
            except Exception:
                return None

    def decode_get_parameter(self, dns_b64: str) -> Optional[bytes]:
        """
        Decodes base64url query parameter according to RFC 8484 / RFC 4648 (handling omitted padding).
        """
        if not dns_b64:
            return None
        try:
            clean_b64 = dns_b64.strip()
            missing_padding = (4 - len(clean_b64) % 4) % 4
            padded_b64 = clean_b64 + ("=" * missing_padding)
            return base64.urlsafe_b64decode(padded_b64.encode("ascii"))
        except Exception:
            return None

    def process_wire_query(self, raw_query: bytes, client_ip: str = "127.0.0.1") -> Optional[bytes]:
        """
        Synchronous processing of a raw DoH wire query:
        Delegates to Orchestrator -> ActionHandler/UpstreamClient -> ResolverMetrics.
        """
        start_time = time.perf_counter()
        query = self.decode_dns_query(raw_query, client_ip)
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
                        raw_query=raw_query,
                        decision=decision,
                        mode="SINKHOLE",
                    )
                else:
                    # ALLOW or SUSPICIOUS
                    response = self.upstream_client.forward_query(raw_query)
                    if response is None:
                        upstream_failed = True
                        response = self.action_handler.create_servfail_response(raw_query)
            except Exception:
                upstream_failed = True
                response = self.action_handler.create_servfail_response(raw_query)
        else:
            # Standalone fallback without orchestrator
            response = self.upstream_client.forward_query(raw_query)
            if response is None:
                upstream_failed = True
                response = self.action_handler.create_servfail_response(raw_query)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if self.metrics:
            self.metrics.record_query(
                protocol=ProtocolType.DOH,
                action=action_decision,
                latency_ms=elapsed_ms,
                cache_hit=cache_hit,
                upstream_failed=upstream_failed,
            )

        return response

    def handle_doh_request(self, domain: str, client_ip: str = "127.0.0.1") -> DNSQuery:
        """
        Legacy skeleton compatibility method.
        """
        return DNSQuery(
            query_id=f"doh-{int(time.time()*1000)%65535:04x}",
            domain=domain.strip().rstrip("."),
            client_ip=client_ip,
            protocol=ProtocolType.DOH,
            qtype="A",
        )


def create_doh_router(server: Optional[DoHServer] = None):
    """
    Creates a FastAPI APIRouter exposing RFC 8484 DoH endpoints (/dns-query).
    """
    if not HAS_FASTAPI:
        return None

    doh_server = server or DoHServer()
    router = APIRouter(tags=["DNS over HTTPS (RFC 8484)"])

    @router.get("/dns-query", summary="RFC 8484 DoH GET Endpoint")
    async def doh_get_handler(
        request: Request,
        dns: Optional[str] = Query(None, description="Base64url encoded DNS query packet"),
    ):
        if not dns:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing 'dns' query parameter in GET request.",
            )

        raw_query = doh_server.decode_get_parameter(dns)
        if not raw_query or len(raw_query) < 12:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or malformed base64url DNS query payload.",
            )

        client_ip = request.client.host if request.client else "127.0.0.1"
        response_bytes = await asyncio.to_thread(doh_server.process_wire_query, raw_query, client_ip)

        if not response_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to parse or process DNS query.",
            )

        return Response(content=response_bytes, media_type=DOH_MEDIA_TYPE)

    @router.post("/dns-query", summary="RFC 8484 DoH POST Endpoint")
    async def doh_post_handler(request: Request):
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in (DOH_MEDIA_TYPE, "application/octet-stream"):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"Unsupported Content-Type '{content_type}'. Expected '{DOH_MEDIA_TYPE}'.",
            )

        raw_query = await request.body()
        if not raw_query or len(raw_query) < 12:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty or malformed binary DNS query body.",
            )

        client_ip = request.client.host if request.client else "127.0.0.1"
        response_bytes = await asyncio.to_thread(doh_server.process_wire_query, raw_query, client_ip)

        if not response_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to parse or process binary DNS query.",
            )

        return Response(content=response_bytes, media_type=DOH_MEDIA_TYPE)

    return router


def create_doh_app(server: Optional[DoHServer] = None):
    """
    Factory creating a lightweight standalone FastAPI app hosting DoH endpoints for testing.
    """
    if not HAS_FASTAPI:
        return None

    app = FastAPI(title="DNSentinel DoH Server (RFC 8484)", version="2.0.0")
    router = create_doh_router(server)
    if router:
        app.include_router(router)
    return app


# Default module router export if FastAPI available
doh_router = create_doh_router() if HAS_FASTAPI else None
