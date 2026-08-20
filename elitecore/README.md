# EliteCore — Member 6: Dashboard & REST API

FastAPI + WebSocket backend and a React/Vite dashboard for the EliteCore DNS
Security project (SIH1524). Built mock-data-first per the Member 6 blueprint,
so it runs standalone right now and only needs its mock provider swapped out
once Members 1–5 deliver real data.

## Running it

**Backend** (FastAPI, SQLite, mock event generator, WebSocket stream):

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate   # .venv\Scripts\activate on plain cmd
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

On first startup it seeds ~90 mock DNS events into `backend/data/elitecore.db`
and starts emitting a new mock event every 1–3 seconds over `/ws/telemetry`.

**Frontend** (React + Vite + Recharts):

```bash
cd frontend
npm install
npm run dev
```

Opens on `http://localhost:5173`, talking to the API at `http://localhost:8000`
(override with a `VITE_API_BASE` env var if needed).

## The data contract

Everything in this module — REST responses, WebSocket frames, the frontend's
TypeScript types — is shaped around `SecurityDecision`:

```json
{
  "id": "evt_001",
  "timestamp": "2026-08-20T12:30:25Z",
  "domain": "xj29akd9.xyz",
  "client_ip": "192.168.1.20",
  "query_type": "A",
  "risk_score": 91,
  "decision": "BLOCK",
  "evidence": {
    "threat_intel": { "matched": true, "confidence": 0.88, "category": "malware" },
    "dga": { "probability": 0.94, "classification": "DGA" },
    "tunneling": { "rate": 0.82, "detected": true }
  },
  "rationale": "Domain matched threat intelligence and showed strong DGA and tunneling characteristics."
}
```

Defined in [`backend/schemas.py`](backend/schemas.py) and mirrored in
[`frontend/src/types/security.ts`](frontend/src/types/security.ts). `decision`
is always one of `ALLOW` / `SUSPICIOUS` / `BLOCK`; `risk_score` is 0–100
(0–29 LOW, 30–59 MEDIUM, 60–79 HIGH, 80–100 CRITICAL).

## Real integration: how teammates plug in

You don't need to touch this codebase to send real data into the dashboard.
Once your module can produce a `SecurityDecision`, POST it to:

```
POST http://<dashboard-host>:8000/api/v1/ingest/decision
Content-Type: application/json

{ ...a SecurityDecision, exactly as shown above... }
```

That single call:
- validates the payload against the contract (a wrong field name, an invalid
  `decision` value like `"DENY"`, or a `risk_score` outside 0-100 gets an
  immediate `422` with details -- so integration bugs show up on your side,
  not as a silently broken dashboard)
- saves it to the same SQLite DB the REST endpoints read from
- broadcasts it over the same WebSocket the mock stream uses, so it appears
  in the live query table instantly, same as a mock event

Re-posting the same `id` (e.g. a retried request) upserts instead of erroring.

Once you're sending real decisions, start the backend with `MOCK_MODE=off`
(`MOCK_MODE=off uvicorn main:app --reload`, or set it in your shell/`.env`)
so the seeded mock rows and the mock stream don't mix with real data in a
demo. Leave it unset/`on` while your module isn't ready yet -- the dashboard
keeps working standalone either way.

## Where the mock data lives (swap points for integration)

| Data | Mock source today | Owner to swap in |
| --- | --- | --- |
| DNS queries + risk scores | `backend/mock_data.py`, `backend/mock_stream.py` | Member 1 (Risk Engine) |
| Resolver metrics (`cache_hit_rate`) | `backend/services/metrics_service.py` | Member 2 |
| Threat-intel stats | `backend/services/evidence_service.py` | Member 3 |
| DGA/ML stats | `backend/services/evidence_service.py` | Member 4 |
| Tunneling evidence + PCAP results | `backend/mock_data.py`, `backend/services/passive_service.py` | Member 5 |

To integrate a real provider, replace the relevant function's body with a call
into the real module — the routes, schemas, and frontend don't need to change
as long as the shape matches `SecurityDecision`.

## How each teammate connects their code

Member 6 (this module) owns the *receiving side* only — the API/WebSocket/DB
and the dashboard that renders whatever they get handed. Nobody else needs to
read this codebase to connect; they just need to know where their piece slots
in. Nothing below is implemented speculatively — only Member 1's path is real
today, because it's the only one whose shape (`SecurityDecision`) the whole
team already agreed on. The rest are documented as open options, to be wired
in once each member's actual setup (same repo vs. separate service, sync vs.
async, etc.) is known — building against a guessed shape would just mean
redoing it later.

### Member 1 — Risk Engine (done, working today)

Real integration already works: their engine POSTs a `SecurityDecision` to
`POST /api/v1/ingest/decision` (see [Real integration](#real-integration-how-teammates-plug-in)
above) every time it makes a decision. Validated, persisted, broadcast live.
Nothing left to build on this end — Member 1 just needs the contract and the
URL.

### Member 2 — Resolver

**Owns:** resolver health — total queries handled, active ports, cache hit %.

**Current state:** `cache_hit_rate` in `GET /api/v1/metrics/summary` is a
hardcoded placeholder (`backend/services/metrics_service.py`); there's no
`active_ports` field yet at all.

**Options once their module exists:**
- *Push*, mirroring Member 1's pattern — they POST periodic snapshots to a
  new `POST /api/v1/ingest/resolver-stats` endpoint (to be added), which
  updates an in-memory/DB value that `metrics_service.py` reads.
- *Pull* — if their resolver exposes its own small stats endpoint or a
  shared file/socket, `metrics_service.py` fetches from it directly instead.

Either way, the only file that changes is `metrics_service.py` plus (for the
push option) one new route — the dashboard and its types don't change.

### Member 3 — Threat Intel

**Owns:** IOC feed size, active IOC count, per-category match distribution.

**Current state:** `total_iocs` / `active_iocs` in `GET /api/v1/intel/stats`
are hardcoded (`backend/services/evidence_service.py::get_intel_stats`);
`matches_today` and `categories` are already computed live from real
`SecurityDecision` data logged via Member 1, so those two are effectively
already "real" as soon as Member 1 is connected.

**Options:** same push-vs-pull choice as Member 2 — either they POST snapshots
to a new `/api/v1/ingest/intel-stats` endpoint, or `evidence_service.py` pulls
from wherever their IOC store lives.

### Member 4 — AI/ML DGA

**Owns:** classifier accuracy, feature-importance breakdown, DGA probability
distribution.

**Current state:** `GET /api/v1/ml/stats` returns a hardcoded `accuracy`
(0.94) and model name; `total_predictions` / `dga_detected` / `normal_domains`
are already computed live from logged decisions. There's no
feature-importance or probability-distribution field yet — that's new surface
to add once their classifier exists and it's clear what shape it outputs.

**Options:** same push-vs-pull pattern as Members 2 and 3.

### Member 5 — Tunneling & Passive Analysis

**Owns:** the actual PCAP/Zeek parsing behind `POST /api/v1/passive/upload-pcap`,
plus real `tunneling` evidence (`rate`, `detected`) inside each `SecurityDecision`.

**Current state:** the upload route (`backend/routes/passive.py`) saves the
uploaded file correctly but hands it to `mock_pcap_result()` in
`backend/services/passive_service.py` instead of a real parser — so the
forensic summary returned today is fabricated, not computed from the file.

This one is the odd one out: it's not Member 5 pushing data *to* Member 6,
it's Member 6's endpoint that needs to call *into* Member 5's analyzer when a
file lands. Two ways that can go, depending on the team's actual setup:

- **Same codebase** — if Member 5's analyzer is a Python function in the
  same repo, `passive_service.py` imports and calls it directly in place of
  the mock, using the already-saved file path from `routes/passive.py`.
- **Separate service** — if Member 5 runs their own process, the upload
  route forwards the file to their API and relays the response back,
  reshaped to `PassiveUploadResult` if needed.

Tunneling evidence inside live `SecurityDecision` events is simpler — that's
just part of the payload Member 1 (or whoever assembles the final decision)
POSTs to `/api/v1/ingest/decision`, using Member 5's numbers as an input.

## REST API

- `GET /api/v1/metrics/summary`
- `GET /api/v1/dns/queries?page=&limit=&decision=&search=`
- `GET /api/v1/dns/queries/{id}` — full evidence for one query
- `GET /api/v1/intel/stats`
- `GET /api/v1/ml/stats`
- `POST /api/v1/passive/upload-pcap` (multipart, `.pcap`/`.pcapng`/`.tsv`)
- `POST /api/v1/ingest/decision` — **the real-integration endpoint**, see above
- `WS /ws/telemetry` — live `SecurityDecision` events, one per 1–3s (mock or real)

## Project layout

```text
elitecore/
├── backend/
│   ├── main.py, config.py, database.py, models.py, schemas.py
│   ├── mock_data.py, mock_stream.py, websocket.py
│   ├── routes/        (metrics, dns, intel, ml, passive)
│   └── services/       (metrics, dns, evidence, passive)
└── frontend/
    └── src/
        ├── components/ (MetricCard, QueryTable, EvidenceModal, UploadModal, charts, ...)
        ├── pages/Dashboard.tsx
        ├── hooks/useTelemetry.ts   (WebSocket client, auto-reconnect w/ backoff)
        ├── services/api.ts
        └── types/security.ts
```
