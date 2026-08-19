# EliteCore — Production-Oriented DNS Threat Detection Platform Prototype
**Problem ID:** SIH1524 | **Team:** EliteCore (6 Members) | **Version:** v2.0 Master SRS Specification

EliteCore is an explainable, production-ready DNS threat-analysis and security filtering platform. It combines real-time multi-protocol DNS listeners (UDP Port 53, DoH RFC 8484, DTLS RFC 8094), threat intelligence feeds (STIX 2.1 / TAXII 2.1), machine learning DGA domain classification (Random Forest), behavioral DNS-tunneling detection (60s sliding window), and unified live/forensic network packet analysis (PCAP / Zeek TSV).

---

## 🏛️ System Architecture & Data Flow

```text
Client DNS Request (UDP / DoH / DTLS)
       │
       ▼
 ┌──────────┐      HIT (< 5ms)
 │DNS Cache ├─────────────────────────┐
 └────┬─────┘                         │
      │ MISS                          ▼
      ▼                       ┌──────────────┐
┌───────────┐                 │  Fast Return │
│Threat Intel│ (Direct Match)  └──────────────┘
└─────┬─────┘
      │
      ▼
┌───────────┐
│ AI/ML DGA │ (12 Lexical Features: Entropy & N-grams)
└─────┬─────┘
      │
      ▼
┌───────────┐
│ Tunneling │ (60s Sliding Window Tracker)
└─────┬─────┘
      │
      ▼
┌───────────────┐
│  Risk Engine  ├─► Risk Score = Min(100, 1.0*Intel + 0.40*ML + 0.35*Tunnel + 0.25*Behavior)
└───────┬───────┘
        │
        ├──► Score >= 70        --> BLOCK (0.0.0.0 Sinkhole IP)
        ├──► 40 <= Score < 70   --> SUSPICIOUS (Allow + Alert Telemetry)
        └──► Score < 40         --> ALLOW (Forward to Upstream DNS 8.8.8.8)
        │
        ▼
┌─────────────────┐     WebSocket / REST      ┌──────────────────┐
│ SQLite Database ├──────────────────────────►│ React Dashboard  │
└─────────────────┘                           └──────────────────┘
```

---

## 👥 Team File Ownership & Permission Matrix

To prevent merge conflicts and ensure parallel development, file ownership is strictly divided among the 6 team members. Members must work in their assigned feature branches and modify only their allowed files.

| Role & Member | Feature Branch | Owned Files & Directories | Permission & Editing Rules |
| :--- | :--- | :--- | :--- |
| **Member 1: Team Lead**<br>(Mohd Saad Khan) | `feature/core-risk-engine` | `shared/schemas.py`<br>`shared/config.py`<br>`core/risk_engine.py`<br>`core/orchestrator.py` | **Allowed to edit core schemas, global risk weights, and parallel orchestrator.** Reviews and approves all PRs into `development`. |
| **Member 2: Resolver Lead** | `feature/dns-resolver` | `resolver/udp_server.py`<br>`resolver/doh_server.py`<br>`resolver/dtls_server.py`<br>`resolver/dns_cache.py`<br>`resolver/upstream_client.py` | **Allowed to edit DNS listeners, TTL cache, and upstream forwarders.** Must not alter shared schemas without Team Lead approval. |
| **Member 3: Threat Intel Lead** | `feature/threat-intel` | `threat_intel/stix_parser.py`<br>`threat_intel/taxii_client.py`<br>`threat_intel/ioc_store.py` | **Allowed to edit STIX/TAXII parsers and in-memory IOC lookups.** Manages offline threat feed snapshots. |
| **Member 4: AI/ML DGA Lead** | `feature/ml-dga` | `ml/feature_extractor.py`<br>`ml/dga_classifier.py`<br>`ml/train_model.py`<br>`ml/dga_rf_v1.pkl` | **Allowed to edit lexical feature extractors, RF classifier, and model bundles.** Maintains ML inference speed (< 8ms). |
| **Member 5: Tunnel & Passive Lead** | `feature/passive-tunneling` | `passive/tunnel_detector.py`<br>`passive/pcap_parser.py`<br>`passive/zeek_parser.py`<br>`passive/batch_analyzer.py` | **Allowed to edit sliding window entropy tracker, PCAP parser, and Zeek TSV parser.** |
| **Member 6: Dashboard & Backend Lead** | `feature/dashboard-ui` | `backend/main.py`<br>`backend/websocket.py`<br>`backend/database.py`<br>`frontend/src/` | **Allowed to edit REST endpoints, WebSocket streams, SQLite logging, and React UI components.** |

---

## 💻 Step-by-Step Complete Clone & Local Setup Guide

Follow these exact commands to clone, configure, and execute the complete system locally.

### 1. Prerequisites Check
Ensure your computer has Python 3.10+ and Node.js 18+ installed:
```bash
python --version
node --version
npm --version
```

---

### 2. Clone the Repository & Checkout Branch
```bash
# Clone the repository
git clone <your-repository-url>
cd EliteCore

# Checkout the development branch
git checkout development
```

---

### 3. Backend Setup & Execution

#### On Windows (PowerShell):
```powershell
# Create Python virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Copy environment variables template
Copy-Item .env.example .env

# Train baseline ML model bundle (if needed)
python ml/train_model.py

# Start FastAPI Telemetry Server & Backend Resolvers
python -m backend.main
```

#### On Linux / macOS (Bash):
```bash
# Create Python virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Copy environment variables template
cp .env.example .env

# Train baseline ML model bundle (if needed)
python ml/train_model.py

# Start FastAPI Telemetry Server & Backend Resolvers
python -m backend.main
```

*The backend server will run on `http://localhost:8000`. You can inspect interactive API documentation at `http://localhost:8000/docs`.*

---

### 4. Frontend Setup & Execution (New Terminal Window)

Open a **second terminal window**, navigate to the `EliteCore` root directory, and run:

```bash
# Navigate to frontend folder
cd frontend

# Install Node modules
npm install

# Start Vite React Dark-Mode Dashboard
npm run dev
```

*The frontend dashboard will run locally at `http://localhost:3000` (or `http://localhost:5173`).*

---

## 📊 Canonical Risk Scoring Formula & Decision Boundaries

$$\text{RiskScore} = \min(100, \text{round}(1.0 \times \text{IntelMatch} + 0.40 \times (\text{ML\_Prob} \times 100) + 0.35 \times \text{TunnelScore} + 0.25 \times \text{BehaviorScore}))$$

- **BLOCK**: Composite Score $\ge 70.0$ or Direct Threat Intel Match ($\text{IntelMatch} = 100$)
- **SUSPICIOUS**: $40.0 \le \text{Composite Score} < 70.0$ (Allowed with monitoring alert badge)
- **ALLOW**: Composite Score $< 40.0$ (Forwarded to upstream resolver `8.8.8.8`)

---

## 📂 Detailed Folder & Subfolder Code Guide

Below is an exhaustive breakdown explaining the code and purpose of every single directory and file in the project.

```text
EliteCore/
│
├── .gitignore                      # Git configuration ignoring bytecode, .venv, node_modules, dist, and .db files
├── .env.example                    # Environment template for ports, upstream resolvers, and risk thresholds
├── requirements.txt                # Python backend dependencies (FastAPI, Scapy, dnspython, scikit-learn, etc.)
├── README.md                       # Comprehensive master documentation, RACI matrix, setup guide, and directory map
│
├── shared/                         # Core Intellectual & Shared Schema Layer (Member 1: Team Lead)
│   ├── __init__.py                 # Package marker for shared utilities
│   ├── config.py                   # System global constants, default network ports, and risk formula weights
│   └── schemas.py                  # Pydantic data contracts (DNSQuery, ThreatIntelResult, MLDgaResult, TunnelResult, SecurityDecision)
│
├── core/                           # Parallel Orchestration & Decision Engine Layer (Member 1: Team Lead)
│   ├── __init__.py                 # Package marker for core engine
│   ├── risk_engine.py              # Canonical Risk Engine implementing the SRS formula and decision boundaries
│   └── orchestrator.py             # Parallel orchestrator coordinating Threat Intel, ML, and Tunneling detectors
│
├── resolver/                       # Multi-Protocol DNS Listeners & Cache Layer (Member 2: Resolver Lead)
│   ├── __init__.py                 # Package marker for resolver modules
│   ├── dns_cache.py                # Thread-safe in-memory TTL cache (< 5ms hit target)
│   ├── udp_server.py               # DNS over UDP (Port 53) listener and packet decoder
│   ├── doh_server.py               # DNS over HTTPS (RFC 8484) server handler skeleton
│   ├── dtls_server.py              # DNS over DTLS (RFC 8094) datagram listener skeleton
│   └── upstream_client.py          # Forwarder client resolving clean domains against 8.8.8.8
│
├── threat_intel/                   # Threat Intelligence & STIX/TAXII Feed Layer (Member 3: Threat Intel Lead)
│   ├── __init__.py                 # Package marker for threat intel modules
│   ├── ioc_store.py                # Sub-2ms in-memory IOC lookup store with local SQLite snapshot fallback
│   ├── stix_parser.py              # STIX 2.1 JSON threat feed parser extracting domain indicators
│   └── taxii_client.py             # TAXII 2.1 REST API client for polling live CTI feeds
│
├── ml/                             # AI/ML DGA Lexical Detection Layer (Member 4: AI/ML DGA Lead)
│   ├── __init__.py                 # Package marker for ML modules
│   ├── feature_extractor.py        # 12-metric lexical feature extractor (Shannon entropy, n-grams, digit ratio, length)
│   ├── dga_classifier.py           # Random Forest classifier wrapper with offline heuristic fallback (< 8ms target)
│   ├── train_model.py              # Model training script generating dga_rf_v1.pkl
│   └── dga_rf_v1.pkl               # Serialized baseline Random Forest model binary bundle
│
├── passive/                        # Behavioral Tunneling & Forensic Ingestion Layer (Member 5: Tunnel Lead)
│   ├── __init__.py                 # Package marker for passive modules
│   ├── tunnel_detector.py          # 60-second sliding window query tracker detecting sub-domain entropy and TXT spikes
│   ├── pcap_parser.py              # Scapy packet parser extracting DNS payloads from raw .pcap files
│   ├── zeek_parser.py              # TSV dns.log parser for Zeek network telemetry
│   └── batch_analyzer.py           # Forensic batch upload processor evaluating historical packet logs
│
├── backend/                        # FastAPI REST API & WebSocket Telemetry Server Layer (Member 6: Dashboard Lead)
│   ├── __init__.py                 # Package marker for backend server
│   ├── main.py                     # FastAPI REST API application hosting query logs, summary metrics, and upload routes
│   ├── database.py                 # Async SQLite telemetry query log database manager
│   └── websocket.py                # Live WebSocket connection manager (/ws/telemetry) broadcasting events in < 5ms
│
└── frontend/                       # React Cyber-Dark Security Operations Center UI (Member 6: Dashboard Lead)
    ├── package.json                # React, Vite, TypeScript, and Lucide-React dependency manifest
    ├── vite.config.ts              # Vite build configuration (Port 3000)
    ├── tsconfig.json               # TypeScript compiler rules
    ├── index.html                  # HTML template with Google Fonts (Inter & JetBrains Mono)
    └── src/                        # React source code root
        ├── App.tsx                 # Main SOC Dashboard layout, state manager, and WebSocket auto-reconnect
        ├── main.tsx                # React DOM entry point
        ├── index.css               # Cyber-dark design system (glassmorphic panels, status badges, pulse animations)
        └── components/             # Reusable UI component library
            ├── Header.tsx          # Status header with live WebSocket indicator and test query triggers
            ├── MetricCards.tsx     # Stat counters for Total Queries, Blocked Threats, Suspicious, Cache Hits, and Latency
            ├── QueryStreamTable.tsx # Real-time query log stream table with status badges and evidence buttons
            ├── EvidenceModal.tsx   # Domain Evidence Inspector Modal displaying explainable AI risk attributions
            └── UploadModal.tsx     # Drag-and-drop file upload modal for PCAP and Zeek network logs
```