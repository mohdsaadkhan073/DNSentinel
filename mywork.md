# 🛡️ Member 1: Team Lead & Core Security Architect Manual (`mywork.md`)
**Project:** DNSentinel (SIH1524) — Production-Oriented DNS Threat Detection Platform Prototype  
**Team Leader:** Mohd Saad Khan (Member 1)  
**Team Name:** EliteCore (6 Members)  
**Role Scope:** Team Leader, Core Security Architect, System Integration Owner, Jury Defense Lead  
**Owned Modules:** `shared/schemas.py`, `shared/config.py`, `core/risk_engine.py`, `core/orchestrator.py`  
**Target SLAs:** $< 100\text{ms}$ Total Lookup Latency, $< 5\text{ms}$ Cache Hits, $F1 \ge 0.95$ DGA Detection, $100\%$ Offline Resilience  

---

## 1. Official Problem Statement & Executive Overview

### Verbatim SIH1524 Problem Description
> *"DNS Filtering service helps block malicious domains and prevent malware from communicating with Command-and-control servers. It also aids in blocking phishing attacks, playing a crucial role in enhancing security and ensuring appropriate content access. The solution should provide a secure DNS resolver that blocks resolution of malicious domain names using blacklists, STIX/TAXII feeds, AI/ML for DGA domains, and DNS tunnelling detection. It must support DNS over UDP, DNS over DTLS, and DNS over HTTPS, maintain an average lookup time within 100ms, support caching, and perform both active query filtering and passive PCAP/Zeek TSV analysis."*

### Leadership Mindset & Intellectual Ownership
As Team Leader and Core Security Architect, Mohd Saad Khan maintains intellectual ownership of the central security pipeline:

$$\text{DNS Query (UDP/DoH/DTLS)} \longrightarrow \text{TTL Cache} \longrightarrow \text{Threat Intel} \longrightarrow \text{ML DGA} \longrightarrow \text{Tunneling} \longrightarrow \text{Risk Engine} \longrightarrow \text{Decision}$$

1. **Define Universal Standards**: Establish universal data contracts (`shared/schemas.py`) on Day 1 so all 5 teammates build their feature branches in parallel without code conflicts.
2. **Build Core Brain**: Develop the Detection Orchestrator (`core/orchestrator.py`) and canonical Risk Engine (`core/risk_engine.py`).
3. **Ensure Integration & Verification**: Lead daily pull request reviews, test end-to-end telemetry pipelines, and enforce the 5-tier failure contingency protocol during jury presentations.

---

## 2. Universal Data Contracts (`shared/schemas.py`)

Member 1 defines the canonical Pydantic schemas shared across all 6 team modules:

```python
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class ProtocolType(str, Enum):
    UDP = "UDP"
    DOH = "DoH"
    DTLS = "DTLS"
    PASSIVE = "PASSIVE"

class ActionDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SUSPICIOUS = "SUSPICIOUS"

class DNSQuery(BaseModel):
    query_id: str
    domain: str
    client_ip: str
    protocol: ProtocolType = ProtocolType.UDP
    qtype: str = "A"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ThreatIntelResult(BaseModel):
    matched: bool = False
    threat_category: Optional[str] = None
    intel_score: float = 0.0  # 0 to 100
    source_feed: Optional[str] = None
    details: Optional[str] = None

class MLDgaResult(BaseModel):
    is_dga: bool = False
    dga_probability: float = 0.0  # 0.0 to 1.0
    model_version: str = "v1.0"
    features: Optional[Dict[str, float]] = None

class TunnelResult(BaseModel):
    is_tunnel: bool = False
    tunnel_score: float = 0.0  # 0 to 100
    entropy: float = 0.0
    query_length: int = 0
    reason: Optional[str] = None

class SecurityDecision(BaseModel):
    decision_id: str
    query: DNSQuery
    action: ActionDecision
    composite_risk_score: float  # 0 to 100
    intel_result: ThreatIntelResult
    ml_result: MLDgaResult
    tunnel_result: TunnelResult
    behavior_score: float = 0.0
    latency_ms: float
    cache_hit: bool = False
    resolved_ip: Optional[str] = None
    rationale: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class MetricsSummary(BaseModel):
    total_queries: int = 0
    blocked_queries: int = 0
    suspicious_queries: int = 0
    allowed_queries: int = 0
    cache_hits: int = 0
    avg_latency_ms: float = 0.0
    dga_detected_count: int = 0
    tunnels_detected_count: int = 0
```

---

## 3. Global System Configuration (`shared/config.py`)

Member 1 configures default ports, network parameters, and risk scoring weights:

```python
import os

# Network Listener Defaults
FASTAPI_HOST = os.getenv("FASTAPI_HOST", "0.0.0.0")
FASTAPI_PORT = int(os.getenv("FASTAPI_PORT", "8000"))
DNS_UDP_PORT = int(os.getenv("DNS_UDP_PORT", "53"))
DNS_DOH_PORT = int(os.getenv("DNS_DOH_PORT", "8443"))
DNS_DTLS_PORT = int(os.getenv("DNS_DTLS_PORT", "853"))

# Upstream Resolver
UPSTREAM_DNS_PRIMARY = os.getenv("UPSTREAM_DNS_PRIMARY", "8.8.8.8")
UPSTREAM_DNS_SECONDARY = os.getenv("UPSTREAM_DNS_SECONDARY", "1.1.1.1")

# Security Decision Boundaries
RISK_THRESHOLD_BLOCK = float(os.getenv("RISK_THRESHOLD_BLOCK", "70.0"))
RISK_THRESHOLD_SUSPICIOUS = float(os.getenv("RISK_THRESHOLD_SUSPICIOUS", "40.0"))

# Risk Formula Weights
WEIGHT_THREAT_INTEL = 1.0
WEIGHT_ML_DGA = 0.40
WEIGHT_TUNNEL = 0.35
WEIGHT_BEHAVIOR = 0.25

# Database & File Paths
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "dnsentinel_telemetry.db")
ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "ml/dga_rf_v1.pkl")
```

---

## 4. Canonical Risk Scoring Engine (`core/risk_engine.py`)

### Mathematical Risk Score Formula

$$\text{RiskScore} = \min\left(100, \text{round}\left(1.0 \times \text{IntelMatch} + 0.40 \times (\text{ML\_Prob} \times 100) + 0.35 \times \text{TunnelScore} + 0.25 \times \text{BehaviorScore}\right)\right)$$

### Decision Boundaries
- **BLOCK** ($\text{RiskScore} \ge 70.0$ or $\text{IntelMatch} = 100$): Returns `0.0.0.0` sinkhole IP.
- **SUSPICIOUS** ($40.0 \le \text{RiskScore} < 70.0$): Resolves query + triggers alert badge in dashboard telemetry.
- **ALLOW** ($\text{RiskScore} < 40.0$): Forwards request to upstream resolver (`8.8.8.8`).

### Python Implementation (`core/risk_engine.py`)
```python
from shared.schemas import ThreatIntelResult, MLDgaResult, TunnelResult, ActionDecision
from shared.config import (
    RISK_THRESHOLD_BLOCK,
    RISK_THRESHOLD_SUSPICIOUS,
    WEIGHT_THREAT_INTEL,
    WEIGHT_ML_DGA,
    WEIGHT_TUNNEL,
    WEIGHT_BEHAVIOR
)

class RiskEngine:
    """
    Canonical Risk Engine for DNSentinel.
    Owned by Member 1 (Team Lead & Core Security Architect).
    """

    @staticmethod
    def calculate_risk(
        intel: ThreatIntelResult,
        ml: MLDgaResult,
        tunnel: TunnelResult,
        behavior_score: float = 0.0
    ) -> tuple[float, ActionDecision, str]:
        
        intel_score = 100.0 if intel.matched else intel.intel_score
        ml_score = ml.dga_probability * 100.0
        tunnel_score = tunnel.tunnel_score

        raw_score = (
            (WEIGHT_THREAT_INTEL * intel_score) +
            (WEIGHT_ML_DGA * ml_score) +
            (WEIGHT_TUNNEL * tunnel_score) +
            (WEIGHT_BEHAVIOR * behavior_score)
        )
        
        composite_score = min(100.0, float(round(raw_score, 2)))

        if intel.matched or composite_score >= RISK_THRESHOLD_BLOCK:
            decision = ActionDecision.BLOCK
            if intel.matched:
                rationale = f"Blocked: Direct Threat Intel match ({intel.threat_category or 'Malicious Indicator'})."
            else:
                rationale = f"Blocked: High composite risk score ({composite_score:.1f} >= {RISK_THRESHOLD_BLOCK})."
        elif composite_score >= RISK_THRESHOLD_SUSPICIOUS:
            decision = ActionDecision.SUSPICIOUS
            rationale = f"Suspicious: Moderate risk score ({composite_score:.1f}). Flagged for monitoring."
        else:
            decision = ActionDecision.ALLOW
            rationale = f"Allowed: Low risk score ({composite_score:.1f}). Domain clean."

        return composite_score, decision, rationale
```

---

## 5. Parallel Detection Orchestrator (`core/orchestrator.py`)

The orchestrator Coordinates Member 2 (Resolver Cache), Member 3 (Threat Intel), Member 4 (AI/ML DGA), and Member 5 (Tunneling):

```python
import time
import uuid
from shared.schemas import DNSQuery, SecurityDecision, ActionDecision, ThreatIntelResult, MLDgaResult, TunnelResult
from core.risk_engine import RiskEngine

class Orchestrator:
    """
    Parallel Threat Detection Orchestrator.
    Owned by Member 1 (Team Lead).
    """

    def __init__(self, ioc_store=None, dga_classifier=None, tunnel_detector=None, dns_cache=None):
        self.ioc_store = ioc_store
        self.dga_classifier = dga_classifier
        self.tunnel_detector = tunnel_detector
        self.dns_cache = dns_cache

    def process_query(self, query: DNSQuery) -> SecurityDecision:
        start_time = time.perf_counter()

        # Step 1: Check DNS Cache (< 5ms Target)
        if self.dns_cache:
            cached_result = self.dns_cache.get(query.domain)
            if cached_result:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                cached_result.query = query
                cached_result.cache_hit = True
                cached_result.latency_ms = float(round(elapsed_ms, 2))
                return cached_result

        # Step 2: Threat Intel Lookup (Member 3)
        if self.ioc_store:
            intel_res = self.ioc_store.lookup(query.domain)
        else:
            intel_res = ThreatIntelResult(matched=False, intel_score=0.0)

        # Fast path if threat match
        if intel_res.matched:
            ml_res = MLDgaResult(is_dga=False, dga_probability=0.0)
            tunnel_res = TunnelResult(is_tunnel=False, tunnel_score=0.0)
        else:
            # Step 3: AI/ML DGA Analysis (Member 4)
            if self.dga_classifier:
                ml_res = self.dga_classifier.predict(query.domain)
            else:
                ml_res = MLDgaResult(is_dga=False, dga_probability=0.0)

            # Step 4: Behavioral Tunneling Detection (Member 5)
            if self.tunnel_detector:
                tunnel_res = self.tunnel_detector.analyze(query)
            else:
                tunnel_res = TunnelResult(is_tunnel=False, tunnel_score=0.0)

        # Step 5: Risk Engine Decision Calculation
        composite_score, action, rationale = RiskEngine.calculate_risk(
            intel=intel_res,
            ml=ml_res,
            tunnel=tunnel_res
        )

        resolved_ip = "0.0.0.0" if action == ActionDecision.BLOCK else "8.8.8.8"
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        decision = SecurityDecision(
            decision_id=str(uuid.uuid4()),
            query=query,
            action=action,
            composite_risk_score=composite_score,
            intel_result=intel_res,
            ml_result=ml_res,
            tunnel_result=tunnel_res,
            latency_ms=float(round(elapsed_ms, 2)),
            cache_hit=False,
            resolved_ip=resolved_ip,
            rationale=rationale
        )

        if action == ActionDecision.ALLOW and self.dns_cache:
            self.dns_cache.set(query.domain, decision)

        return decision
```

---

## 6. Team RACI & Subsystem Integration Matrix

| Teammate & Role | Module File | How Member 1 Interacts with Subsystem |
| :--- | :--- | :--- |
| **Member 2: Resolver Lead** | `resolver/udp_server.py`<br>`resolver/dns_cache.py` | Member 2's DNS listeners pass incoming packets to `orchestrator.process_query()`. On `BLOCK`, returns sinkhole `0.0.0.0`. |
| **Member 3: Threat Intel Lead** | `threat_intel/ioc_store.py` | `orchestrator` calls Member 3's `lookup(domain)` for sub-2ms in-memory IOC lookups. |
| **Member 4: AI/ML DGA Lead** | `ml/dga_classifier.py` | `orchestrator` calls Member 4's `predict(domain)` to acquire Random Forest probability ($<8\text{ms}$ inference). |
| **Member 5: Tunnel & Passive Lead** | `passive/tunnel_detector.py`<br>`passive/batch_analyzer.py` | `orchestrator` invokes Member 5's sliding window tracker and batch PCAP/Zeek analyzer. |
| **Member 6: Dashboard Lead** | `backend/main.py`<br>`backend/websocket.py` | Member 1 passes `SecurityDecision` events to Member 6's WebSocket broadcaster and SQLite database logger. |

---

## 7. 96-Hour Sprint Execution Plan (Hours 01 to 96)

```text
DAY 01: SETUP & CONTRACTS (Hours 01 — 24)
├── Hours 01 - 12: Set up directory tree, git branches, and write shared/schemas.py & config.py.
└── Hours 13 - 24: Write mock orchestrator.py so Member 2 (Resolver) can connect active listeners.

DAY 02: CORE BRAIN & PARALLEL PIPELINE (Hours 25 — 48)
├── Hours 25 - 36: Implement core/risk_engine.py. Connect Member 3 IOC store and Member 4 ML model.
└── Hours 37 - 48: Integrate Member 5 Tunneling detector. Verify end-to-end query execution (Request -> Decision -> Log).

DAY 03: PASSIVE INGESTION & BENCHMARKING (Hours 49 — 72)
├── Hours 49 - 60: Audit SIH requirements. Verify PCAP/Zeek batch ingestion runs through orchestrator.
└── Hours 61 - 72: Review Member 6 Dashboard Evidence Modal. Benchmark latency (< 100ms average).

DAY 04: BACKUP CONTINGENCY & JURY DRILLS (Hours 73 — 96)
├── Hours 73 - 84: Configure local SQLite DB & pre-cached threat feeds for 100% offline demonstration.
└── Hours 85 - 96: Lead slide presentation dry-runs and technical Q&A defense drills with all 6 members. Freeze code.
```

---

## 8. 5-Tier Demo Failure & Backup Contingency Protocol

| Tier & Scenario | Contingency Backup Strategy (Mohd Saad Khan) |
| :--- | :--- |
| **Tier 1: Live DNS Interception Fails** | Immediately switch to the Passive PCAP / Zeek Drag-and-Drop Ingestion card on the Web Dashboard. |
| **Tier 2: AI/ML Model Exception** | Fall back to local lexical rule heuristics (`entropy > 3.8`) without crashing the resolver. |
| **Tier 3: External Threat Feed API Down** | Switch automatically to local SQLite threat snapshot DB stored on disk (`ioc_snapshot.json`). |
| **Tier 4: Venue Internet Drops** | System operates with 100% offline capability (local SQLite DB, local ML pickle model, local mock resolver). |
| **Tier 5: Web Dashboard UI Crashes** | Demonstrate live query evaluations via FastAPI REST endpoint (`POST /api/v1/dns/evaluate`) or terminal logs. |

---

## 9. Master Presentation & Jury Defense Playbook

### Verbatim 5-Minute Pitch Script for Mohd Saad Khan

> **[0:00 - 1:00] INTRO & PROBLEM:**  
> *"Respected Judges, I am Mohd Saad Khan, Team Lead of EliteCore. We present DNSentinel (SIH1524): a Production-Oriented DNS Threat Detection Platform Prototype. DNS is the Internet's phonebook, but malware abuses it for Command-and-Control communication, DGA domain generation, and DNS tunneling exfiltration."*
>
> **[1:00 - 2:30] INNOVATION & MULTI-PROTOCOL RESOLUTION:**  
> *"Commercial security tools act as binary black boxes. DNSentinel is an explainable platform. Our resolver supports unencrypted DNS over UDP, encrypted DNS over HTTPS (DoH RFC 8484), and encrypted DNS over DTLS (RFC 8094)."*
>
> **[2:30 - 3:30] UNIFIED ACTIVE & PASSIVE ENGINE:**  
> *"Crucially, real-time DNS requests and historical network files (PCAP & Zeek TSV) run through the exact same intelligence engine. In-memory TTL caching resolves clean queries in under 5ms, keeping average lookup latency well under 100ms."*
>
> **[3:30 - 5:00] DEMO & CONCLUSION:**  
> *"Let us demonstrate live security scenarios on our Web Dashboard: clean domain resolution, direct STIX threat matches, zero-day DGA detection, DNS tunneling alerts, and PCAP forensic file uploads. Thank you!"*

### Top Jury Technical Questions & Verbatim Defense Answers

1. **Q1: Why build this when Cloudflare 1.1.1.1 or Cisco Umbrella exist?**
   > *"We built an explainable security engine. Commercial resolvers drop queries silently as black boxes. DNSentinel exposes the evidence behind every decision (DGA probability, subdomain entropy, tunneling score) and evaluates active live traffic and passive PCAP files through the exact same pipeline."*

2. **Q2: How do you guarantee lookup latency under 100ms?**
   > *"Through a 3-tier architecture: 1) Thread-safe in-memory TTL cache (< 5ms hits). 2) Asynchronous parallel execution (`asyncio.gather`). 3) Lightweight lexical feature extraction (< 8ms inference)."*

3. **Q3: Are you supporting DNS over TLS or DNS over DTLS?**
   > *"Our primary datagram protocol specified by SIH1524 is DNS over DTLS (RFC 8094), alongside DNS over UDP and DNS over HTTPS (DoH RFC 8484)."*

4. **Q4: How do you detect DNS Tunneling?**
   > *"Our behavioral engine tracks sliding-window query volume per source IP, subdomain Shannon entropy, query label lengths, and frequency of high-payload record types like TXT and NULL."*

5. **Q5: How do you prevent false positives?**
   > *"We use a weighted composite scoring formula rather than relying solely on ML. An elevated ML score contributes 40% to the total score, preventing clean domains from being blocked unless confirmed by threat feeds or tunneling heuristics."*
