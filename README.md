# WebAppBH

A modular, event-driven Bug Bounty Framework built for automated reconnaissance, vulnerability scanning, and exploit chaining. WebAppBH orchestrates 11 specialized Docker workers through a FastAPI control plane, with real-time monitoring via a Next.js command-and-control dashboard.

## Features

- **Automated Recon Pipeline** — Subdomain enumeration, port scanning, content discovery, and technology fingerprinting across 7 sequential stages
- **11 Specialized Workers** — Recon, web app testing, fuzzing, API testing, vulnerability scanning, mobile analysis, cloud enumeration, network scanning, config management, exploit chaining, and reporting
- **Real-Time C2 Dashboard** — Next.js interface with live SSE streaming, campaign tree view, worker management console, and findings tables
- **Event-Driven Architecture** — Redis Streams with consumer groups for reliable task distribution and inter-worker coordination
- **Scope-Aware Scanning** — Built-in scope manager validates all targets against domain, CIDR, URL, and blacklist rules before execution
- **40+ Integrated Security Tools** — Nuclei, sqlmap, ffuf, Kiterunner, Playwright, MobSF, Frida, Metasploit, and more
- **Structured Reporting** — Automated PDF and Markdown report generation with vulnerability aggregation
- **Worker Lifecycle Management** — Docker SDK integration for spawning, pausing, stopping, and restarting workers with health monitoring and zombie cleanup

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│  Dashboard   │────▶│ Orchestrator │────▶│  Redis Streams   │
│  (Next.js)   │◀─SSE│  (FastAPI)   │     │  (Message Broker) │
└─────────────┘     └──────┬───────┘     └────────┬─────────┘
                           │                      │
                    ┌──────▼───────┐        ┌─────▼──────┐
                    │  PostgreSQL  │        │  Workers   │
                    │  (12 tables) │◀───────│  (Docker)  │
                    └──────────────┘        └────────────┘
```

**Data Flow:** Target submitted via dashboard → orchestrator writes profile + pushes task to Redis → worker picks up message → runs tool pipeline → results written to DB → SSE events streamed to dashboard in real-time.

## Technologies

| Layer | Stack |
|-------|-------|
| **Orchestrator** | Python 3.10, FastAPI, Uvicorn, Docker SDK, SSE |
| **Database** | PostgreSQL 15, SQLAlchemy 2.0 (async), asyncpg |
| **Messaging** | Redis 7 (Streams + consumer groups) |
| **Dashboard** | Next.js 16, React 19, TypeScript, Tailwind CSS v4, Zustand, TanStack Table |
| **Workers** | Python, Go, Rust — compiled security tools in multi-stage Docker builds |
| **Infrastructure** | Docker Compose, custom bridge network, health checks |

## Workers

| Worker | Purpose | Key Tools |
|--------|---------|-----------|
| **recon-core** | Subdomain discovery, port scanning, crawling | subfinder, amass, httpx, naabu, katana, massdns |
| **webapp-worker** | Frontend/DOM analysis, XSS detection | Playwright, dalfox, linkfinder, secretfinder |
| **fuzzing-worker** | Content discovery, parameter fuzzing | ffuf, feroxbuster, arjun, crlfuzz |
| **api-worker** | REST/GraphQL/SOAP testing | Kiterunner, graphql-cop, jwt_tool, CORScanner |
| **vuln-scanner** | Template-based vulnerability scanning | Nuclei, sqlmap, tplmap, commix, SSRFmap |
| **mobile-worker** | Mobile app SAST + DAST | MobSF, Frida, docker-android |
| **cloud-worker** | Cloud resource enumeration | AWS/Azure/GCP SDKs |
| **network-worker** | Port enumeration, service fingerprinting | nmap, naabu |
| **config-mgmt** | Configuration security validation | ffuf, nmap, custom auditors |
| **chain-worker** | Multi-tool exploit chaining | Metasploit, zaproxy |
| **reporting-worker** | Report generation | Jinja2, WeasyPrint, ReportLab |

## Usage

### Quick Start

```bash
# Clone and start the full stack
git clone <repo-url> && cd WebAppBH
docker compose up --build
```

The dashboard is available at `http://localhost:3000` and the API at `http://localhost:8001`.

### Run Individual Services

```bash
# Infrastructure only
docker compose up postgres redis

# Orchestrator API
docker compose up orchestrator

# Dashboard
docker compose up dashboard

# Specific worker
docker compose up recon-core
```

### Development

```bash
# Install shared library (editable)
pip install -e shared/lib_webbh
pip install -e "shared/lib_webbh[dev]"    # includes pytest

# Dashboard development
cd dashboard && npm install && npm run dev

# Run tests
pytest
pytest tests/test_scope.py -k "test_subfinder"
```

### API

All endpoints are prefixed with `/api/v1/` and require an `X-API-KEY` header.

```bash
# Create a target
curl -X POST http://localhost:8001/api/v1/targets \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"company_name": "Example Corp", "base_domain": "example.com"}'

# List assets
curl http://localhost:8001/api/v1/assets \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY"

# Stream events (SSE)
curl http://localhost:8001/api/v1/stream/1 \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `webbh_admin` | Database user |
| `DB_PASS` | `changeme` | Database password |
| `DB_NAME` | `webbh` | Database name |
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `WEB_APP_BH_API_KEY` | *(auto-generated)* | API authentication key |
| `TOOL_TIMEOUT` | `600` | Tool execution timeout (seconds) |
| `COOLDOWN_HOURS` | `24` | Cooldown between re-scans |

## Project Structure

```
WebAppBH/
├── shared/lib_webbh/       # Core library (DB models, messaging, scope, logging)
├── orchestrator/            # FastAPI control plane + event engine
├── workers/
│   ├── recon_core/          # Reconnaissance pipeline
│   ├── webapp_worker/       # Web application testing
│   ├── fuzzing_worker/      # Content discovery + fuzzing
│   ├── api_worker/          # API security testing
│   ├── vuln_scanner/        # Vulnerability scanning
│   ├── mobile_worker/       # Mobile app analysis
│   ├── cloud_worker/        # Cloud enumeration
│   ├── network_worker/      # Network scanning
│   ├── chain_worker/        # Exploit chaining
│   └── reporting_worker/    # Report generation
├── dashboard/               # Next.js C2 interface
├── docker/                  # Dockerfiles (one per service)
├── docs/plans/              # Phase specs, design docs, implementation plans
└── tests/                   # Test suite
```
