# Apex-SOC

![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38BDF8?style=flat-square&logo=tailwindcss&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%C2%AE-FF0000?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsMTAgNSAxMC01TTIgMTJsMTAgNSAxMC01Ii8+PC9zdmc+)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> A stateful, MITRE ATT&CK-mapped Security Operations Center you can run on your laptop. Not a log viewer — a correlation engine.

---

## Why I Built This

A single failed SSH login is noise. Twenty failed SSH logins is still noise — every public-facing server collects those in under a minute. What is **not** noise is this sequence, from the same source IP, inside a five-minute window:

```
23:41:02  Failed password for root from 203.0.113.44 port 22
23:41:05  Failed password for root from 203.0.113.44 port 22
...       (×20 more)
23:42:19  Accepted password for root from 203.0.113.44 port 22
23:42:31  sudo: root : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
```

That is an active breach. Any analyst who has spent time in a SOC knows the difference immediately. The problem is that most log pipelines don't — they emit an alert for each individual event and leave the correlation work to a human staring at a SIEM dashboard.

I built Apex-SOC because I wanted to engineer a system that performs **stateful event correlation across time**, not just per-event rule matching. The engine tracks behavioral chains per entity (source IP), promotes multi-stage sequences to high-fidelity incidents, maps them to **MITRE ATT&CK** techniques, and scores them with a quantitative risk formula. The frontend gives you the full picture in real time. The whole thing deploys with a single command.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Docker Network: soc-net                     │
│                                                                │
│  ┌──────────────────────────┐    ┌────────────────────────┐   │
│  │   backend · FastAPI      │◄───│  frontend · React+Nginx │   │
│  │   Port 8000              │    │  Port 80               │   │
│  │                          │    │                        │   │
│  │  ┌────────────────────┐  │    │  TopStats              │   │
│  │  │  Detection Engine  │  │    │  EventTimeline         │   │
│  │  │  14 Sigma rules    │  │    │  TopAttackers          │   │
│  │  │  MITRE mapping     │  │    │  IncidentFeed          │   │
│  │  └────────┬───────────┘  │    │  LogIngestor           │   │
│  │           │              │    └────────────────────────┘   │
│  │  ┌────────▼───────────┐  │                                 │
│  │  │ Correlation Engine │  │                                 │
│  │  │ 5-min sliding      │  │                                 │
│  │  │ window · per-IP    │  │                                 │
│  │  │ state tracking     │  │                                 │
│  │  └────────────────────┘  │                                 │
│  └──────────────────────────┘                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## The Correlation Engine

This is the core of the project. Everything else — the API, the frontend, the Docker setup — supports it.

### The Problem With Per-Event Rules

Traditional SIEM rules fire on individual events. A rule that says "alert on failed SSH login" will generate hundreds of low-value alerts on any internet-facing server. An analyst learns to ignore them. The actual signal — the _sequence_ of events that constitutes a real attack — gets buried.

The correlation engine solves this by maintaining **per-entity state across time**. Each source IP gets its own `EntityState` object that tracks the behavioral chain it is building inside a rolling five-minute window.

### The Sliding Window

```
Time ──────────────────────────────────────────────────────────────►
     │◄──────────── 5 minutes (300s) ─────────────────────────────►│

     [event₁] [event₂] ... [eventₙ]   ← tracked per source IP
                                         older events expire and
                                         fall out of the window
```

When an event arrives, the engine:
1. Purges expired events from that IP's state
2. Classifies the new event against the behavioral chain flags
3. Evaluates whether the **promotion gate** has been crossed
4. If yes — emits a `CRITICAL` incident with the full chain as evidence

### The Attack Chain

I track three behavioral flags per entity. All three must be `True` within the window to promote an incident:

```
 Stage 1                Stage 2               Stage 3
─────────              ─────────             ───────────
 T1110                  T1078                 T1548.003
 Brute Force    ──►     Valid Account  ──►    Sudo / Abuse
 (≥10 failures)         (auth success)        of Elevation
      │                      │                     │
      ▼                      ▼                     ▼
 has_failed_logins=True  has_successful_login=True  has_privilege_escalation=True
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │ INCIDENT PROMOTED│
                                               │ Severity: CRITICAL│
                                               └─────────────────┘
```

The threshold for "brute force" is **≥10 failed logins**. I chose this number deliberately — it's high enough to filter out mistyped passwords and low enough to catch the automated credential stuffing tools that typically run at that cadence.

### Risk Score Formula

When an incident is promoted, I assign a **quantitative risk score** in the range `[0, 100]`. The formula has three components:

```
Risk = (Sₑᵥ × 40) + (Fᵣₑq × 30) + (Aₛₛₑₜ × 30)
```

| Component | Variable | Calculation | Max Pts |
|-----------|----------|-------------|---------|
| **Severity** | `Sₑᵥ` | Normalised max alert severity: `INFO=0.0 · LOW=0.25 · MED=0.5 · HIGH=0.75 · CRIT=1.0` | 40 |
| **Frequency** | `Fᵣₑq` | `min(failed_logins / 50, 1.0)` — saturates at 50 events | 30 |
| **Asset Value** | `Aₛₛₑₜ` | Hostname tier: `prod/db=1.0 · web/api=0.75 · dev=0.25 · test=0.10` | 30 |

**Example — the live breach I showed above:**

```python
Sₑᵥ   = 1.0   # CRITICAL max severity
Fᵣₑq  = min(11/50, 1.0) = 0.22
Aₛₛₑₜ = 1.0   # hostname contains "prod"

Risk  = (1.0 × 40) + (0.22 × 30) + (1.0 × 30)
      = 40 + 6.6 + 30
      = 76.6 / 100
```

This matches the live output from the engine exactly. A score of 76.6 on a prod server is immediately actionable. A score of 12 on a dev box is not — and the formula reflects that correctly.

### MITRE ATT&CK Coverage

The detection engine contains 13 Sigma-like rules. I'm not using every MITRE technique — I'm covering the ones that actually show up in post-breach forensics of SSH-based intrusions:

| Rule | Technique | Tactic |
|------|-----------|--------|
| Brute Force — Failed Password | **T1110** | Credential Access |
| Windows Logon Failure (4625) | **T1110** | Credential Access |
| Successful Auth After Failure | **T1078** | Defense Evasion |
| Sudo Command Execution | **T1548.003** | Privilege Escalation |
| Windows Special Privileges (4672) | **T1548** | Privilege Escalation |
| SSH Tunneling / Port Forward | **T1021.004** | Lateral Movement |
| Port Scan | **T1046** | Discovery |
| SQL Injection (Nginx) | **T1190** | Initial Access |
| XSS Attempt (Nginx) | **T1059.007** | Execution |
| Path Traversal (Nginx) | **T1083** | Discovery |
| C2 — Suspicious Port (4444/1337) | **T1071** | Command and Control |
| Cron Modification | **T1053.003** | Persistence |
| New Account Created (useradd/4720) | **T1136.001** | Persistence |

---

## Tech Stack

### Backend — Python / FastAPI

I chose FastAPI because I needed a typed, async-capable API with automatic schema generation. The alternative would have been Flask, which would have required more boilerplate for the same result. The backend is intentionally stateless at the HTTP layer — all correlation state lives in the in-memory `CorrelationEngine` singleton, which is thread-safe.

```
backend/
├── main.py                  # App factory, CORS, lifespan hooks
├── models/schemas.py        # Pydantic v2: LogEvent, Alert, Incident
├── api/routers/
│   ├── ingest.py            # POST /api/ingest, POST /api/ingest/batch
│   └── dashboard.py         # GET /api/stats|incidents|top-ips|events
└── core/
    ├── detection.py         # 13 Sigma-like rules + MITRE mapping
    └── correlation.py       # Sliding-window engine + risk formula
```

**Key implementation details:**
- **Pydantic v2** for strict input validation on every ingested event. Malformed timestamps, unknown source types, and missing required fields are all rejected at the boundary.
- The `CorrelationEngine` uses a `threading.Lock` around all state mutations so it is safe under Uvicorn's multi-worker configuration.
- A background GC thread runs every 60 seconds to evict stale entity states, keeping memory bounded.

### Frontend — React 18 + Vite + TailwindCSS

The frontend polls the backend every five seconds. It is deliberately not using WebSockets — polling is simpler, easier to debug, and sufficient for a dashboard that refreshes at human timescales. I'd add WebSockets if I needed sub-second latency.

```
frontend/src/
├── components/
│   ├── DashboardLayout.jsx  # Shell: navbar, grid, skeleton states
│   ├── TopStats.jsx         # Three metric cards with neon accent glows
│   ├── EventTimeline.jsx    # Recharts area chart + automatic spike detection
│   ├── TopAttackers.jsx     # IP risk table with inline progress bars
│   ├── IncidentFeed.jsx     # Expandable incident cards + SVG arc gauge
│   └── LogIngestor.jsx      # Dev tool: fire test events from the browser
├── hooks/useSocData.js      # Polling hook with cleanup on unmount
└── utils/severity.js        # Colour mapping, event bucketing for chart
```

### Docker — Multi-Stage Builds

Both images use multi-stage builds to keep the runtime image small and the attack surface minimal.

**Backend image:** Python 3.12-slim builder installs dependencies, the runtime stage copies only the installed packages and application code. The container runs as a **non-root user**.

**Frontend image:** Node 20 builder runs `npm run build` (Vite), the Nginx runtime serves the static bundle. The Nginx config handles API proxying (`/api/*` → `backend:8000`), gzip, security headers (`X-Frame-Options`, `X-Content-Type-Options`), and SPA fallback routing.

---

## DevSecOps Pipeline

Every push to the repository goes through a four-job GitHub Actions pipeline. I treat this as non-optional — a project that can't be verified by CI is a project I don't trust in production.

```
git push
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│  Job 1: Python Quality                                          │
│                                                                 │
│  flake8 ──► bandit (security scan) ──► pytest (21 unit tests)  │
│                                                                 │
│  Bandit fails the build on any HIGH severity finding.          │
│  pytest covers: risk formula math, rule matching, full         │
│  attack-chain promotion, duplicate promotion prevention.        │
└───────────────────┬─────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────┐
│  Job 2: Frontend Build                                          │
│                                                                 │
│  npm ci ──► eslint ──► vite build                              │
│                                                                 │
│  Verifies the bundle compiles cleanly. Uploads dist/ artifact. │
└───────────────────┬─────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────┐
│  Job 3: Docker Build + Smoke Test                               │
│                                                                 │
│  docker buildx (backend) ──► docker buildx (frontend)          │
│       │                                                         │
│       └──► Run backend container ──► curl /api/health          │
│                                      Must return 200 OK        │
│                                                                 │
│  Both builds use GitHub Actions cache (type=gha) to avoid      │
│  re-downloading layers on every run.                           │
└───────────────────┬─────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────┐
│  Job 4: Dependency Audit                                        │
│                                                                 │
│  pip safety (Python CVE check) + npm audit --audit-level=high  │
└─────────────────────────────────────────────────────────────────┘
```

The pipeline produces two artifacts on every run: the Bandit security report (JSON) and the compiled frontend bundle. If any job in the chain fails, the Docker build does not run.

---

## API Reference

The backend exposes a self-documenting OpenAPI spec at `/api/docs`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ingest` | Ingest a single normalised log event |
| `POST` | `/api/ingest/batch` | Ingest up to 500 events in one request |
| `GET` | `/api/stats` | Aggregated counts for dashboard cards |
| `GET` | `/api/incidents` | List of all promoted incidents |
| `GET` | `/api/top-ips` | Source IPs ranked by risk score |
| `GET` | `/api/events` | Recent event stream for the timeline chart |
| `GET` | `/api/health` | Container health check endpoint |

### Simulating a Full Breach Chain

This is the fastest way to verify the engine works end-to-end. Run these from a terminal:

```bash
# Stage 1 — Brute force (fire this 11 times, or use a loop)
for i in $(seq 1 11); do
  curl -s -X POST http://localhost:8000/api/ingest \
    -H "Content-Type: application/json" \
    -d '{
      "source": "linux_auth",
      "source_ip": "10.0.0.1",
      "username": "root",
      "hostname": "prod-web-01",
      "message": "Failed password for root from 10.0.0.1 port 22 ssh2"
    }' | jq .alerts_generated
done

# Stage 2 — Credential compromise
curl -s -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "linux_auth",
    "source_ip": "10.0.0.1",
    "hostname": "prod-web-01",
    "message": "Accepted password for root from 10.0.0.1 port 22 ssh2"
  }'

# Stage 3 — Privilege escalation → incident_promoted: true
curl -s -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "linux_auth",
    "source_ip": "10.0.0.1",
    "hostname": "prod-web-01",
    "message": "sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
  }' | jq '{incident_promoted, incident_id}'
```

The final response will contain `"incident_promoted": true`. Query `/api/incidents` to see the full incident object with risk score, attack chain, affected hosts, and MITRE technique list.

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/your-handle/apex-soc.git
cd apex-soc
docker compose up --build
```

- **Dashboard:** http://localhost
- **API docs (Swagger):** http://localhost:8000/api/docs

The frontend service waits for the backend health check before starting, so the order is handled automatically.

### Local Development

```bash
# Terminal 1 — Backend
cd backend
pip install -r requirements.txt -r requirements-dev.txt
uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend
npm install
npm run dev
# http://localhost:3000
```

### Running Tests

```bash
cd backend
pytest -v                            # 21 unit tests

flake8 . --max-line-length=100       # Lint

bandit -r . --exclude ./tests -ll    # Security scan
```

---

## Project Structure

```
apex-soc/
│
├── backend/
│   ├── main.py
│   ├── models/schemas.py
│   ├── api/routers/
│   │   ├── ingest.py
│   │   └── dashboard.py
│   ├── core/
│   │   ├── detection.py
│   │   └── correlation.py
│   ├── tests/
│   │   └── test_correlation.py     ← 21 tests, 100% pass
│   ├── Dockerfile
│   ├── requirements.txt
│   └── requirements-dev.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/             ← 6 components
│   │   ├── hooks/useSocData.js
│   │   └── utils/severity.js
│   ├── Dockerfile
│   └── nginx.conf
│
├── docker-compose.yml
├── .github/workflows/ci.yml
└── README.md
```

---

## Known Limitations

I want to be direct about what this system does not do:

- **No persistence.** All state is in-memory. Restarting the backend loses all events, incidents, and entity states. Adding a Redis backend or writing incidents to a SQLite database would fix this, and is the obvious next step.
- **Single-node only.** The `CorrelationEngine` is a singleton with an in-process lock. Running multiple Uvicorn workers behind a load balancer would split state across processes and break correlation. You'd need to move state to a shared external store.
- **No authentication on the API.** This is intentional for a local lab setup. Before exposing this on a network, add an API key middleware or an OAuth layer in front of the FastAPI app.
- **Sliding window uses wall-clock time.** If the backend is under heavy load and event processing is delayed, some events might expire from the window before the chain completes. For production use, you'd want to use event timestamps rather than arrival time.

---


