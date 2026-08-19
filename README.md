# EliteCore — Production-Oriented DNS Threat Detection Platform Prototype
**Problem ID:** SIH1524 | **Team:** EliteCore (6 Members)

EliteCore is an explainable DNS threat-analysis and security filtering platform. It combines real-time DNS listeners (UDP, DoH, DTLS), threat intelligence feeds (STIX 2.1 / TAXII 2.1), machine learning DGA domain classification (Random Forest), behavioral DNS-tunneling detection, and forensic packet analysis (PCAP / Zeek TSV).

---

## 🏛️ System Architecture

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
│ AI/ML DGA │ (Lexical Inference)
└─────┬─────┘
      │
      ▼
┌───────────┐
│ Tunneling │ (Entropy & Window Tracker)
└─────┬─────┘
      │
      ▼
┌───────────────┐
│  Risk Engine  ├─► Risk Score = Min(100, 1.0*Intel + 0.40*ML + 0.35*Tunnel + 0.25*Behavior)
└───────┬───────┘
        │
        ├──► Score >= 70  --> BLOCK (0.0.0.0 Sinkhole)
        ├──► 40 <= Score < 70 --> SUSPICIOUS (Allow + Telemetry Flag)
        └──► Score < 40   --> ALLOW (Forward to Upstream DNS 8.8.8.8)
        │
        ▼
┌─────────────────┐      WebSocket / REST      ┌──────────────────┐
│ SQLite Database ├───────────────────────────►│ React Dashboard  │
└─────────────────┘                            └──────────────────┘
```

---

## 👥 Team RACI Responsibility Matrix

| Role | Lead | Owned Directory / Module | Accountabilities |
| :--- | :--- | :--- | :--- |
| **Member 1** | Team Lead (Mohd Saad Khan) | `shared/`, `core/` | Architecture ownership, shared Pydantic schemas, parallel orchestrator, risk scoring formula, jury presentation. |
| **Member 2** | Resolver Lead | `resolver/` | DNS over UDP (Port 53), DoH (RFC 8484), DNS over DTLS (RFC 8094), in-memory TTL cache (< 5ms hits). |
| **Member 3** | Threat Intel Lead | `threat_intel/` | STIX 2.1 parser, TAXII 2.1 REST client, sub-2ms in-memory IOC lookup store, local SQLite snapshot DB. |
| **Member 4** | AI/ML DGA Lead | `ml/` | 12-metric lexical feature extractor (entropy, n-grams), Random Forest classifier (> 95% F1), offline model bundle. |
| **Member 5** | Tunnel & Passive Lead | `passive/` | Behavioral tunneling detector (60s sliding window), PCAP & Zeek TSV log ingestion pipeline. |
| **Member 6** | Dashboard & Backend Lead | `backend/`, `frontend/` | FastAPI REST server, WebSocket stream (/ws/telemetry), React dark-mode dashboard UI, Domain Evidence Modal. |

---

## 🌿 Git Branching & Workflow Rules

- **Branch Naming**:
  - Member 1: `feature/core-risk-engine`
  - Member 2: `feature/dns-resolver`
  - Member 3: `feature/threat-intel`
  - Member 4: `feature/ml-dga`
  - Member 5: `feature/passive-tunneling`
  - Member 6: `feature/dashboard-ui`
- **Workflow**:
  1. Work exclusively inside your assigned `feature/<name>` branch.
  2. Pull daily from `development`: `git pull origin development`
  3. Format commit messages clearly: `feat(resolver): add UDP server listener`, `fix(ml): update feature extraction bounds`.
  4. Create Pull Requests to `development` for review before merging into `main`.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ & npm

### 2. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Run FastAPI Server & Telemetry Backend
python -m backend.main
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## 📊 Canonical Risk Scoring Formula

$$\text{RiskScore} = \min(100, \text{round}(1.0 \times \text{IntelMatch} + 0.40 \times (\text{ML\_Prob} \times 100) + 0.35 \times \text{TunnelScore} + 0.25 \times \text{BehaviorScore}))$$

- **BLOCK**: Risk Score $\ge 70$ or Direct Threat Intel Match ($\text{IntelMatch} = 100$)
- **SUSPICIOUS**: $40 \le \text{Risk Score} < 70$ (Allowed with alert badge)
- **ALLOW**: Risk Score $< 40$ (Forwarded to upstream resolver)