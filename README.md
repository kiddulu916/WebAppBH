# WebAppBH

A modular, event-driven Bug Bounty Framework that automates the full offensive security lifecycle — from passive reconnaissance through exploit chaining and report generation. WebAppBH orchestrates 20+ specialized Docker workers through a FastAPI control plane, with real-time monitoring via a Next.js command-and-control dashboard.

## Features

- **WSTG-Aligned Worker Architecture** — Workers map to OWASP Web Security Testing Guide sections, covering information gathering, identity management, authentication, authorization, session management, input validation, error handling, cryptography, business logic, and client-side testing
- **LLM-Powered Reasoning** — Local Ollama inference (Qwen3:14b default) analyzes vulnerabilities across 10 dimensions: severity re-assessment, exploitability, false-positive detection, chain hypotheses, next steps, bounty estimates, duplicate detection, OWASP/CWE mapping, report readiness, and asset criticality
- **Exploit Chain Discovery** — Chain worker correlates escalation contexts across workers, builds multi-step attack paths, and surfaces them as an interactive attack graph via the API
- **Adaptive Scan Playbooks** — Four built-in playbooks (`wide_recon`, `deep_webapp`, `api_focused`, `cloud_first`) plus custom user-defined playbooks; per-tool hit-rate tracking drives adaptive tool selection
- **Real-Time C2 Dashboard** — Next.js interface with live SSE streaming, campaign tree view, findings tables, attack-graph visualization, and bounty submission tracking
- **Event-Driven Architecture** — Redis Streams with consumer groups for reliable task distribution, priority queuing, and inter-worker coordination
- **Scope-Aware Scanning** — Built-in scope manager validates every target against domain, CIDR, URL, and blacklist rules before any tool executes; violations are logged to the database
- **OOB Callback Server** — Built-in out-of-band interaction listener (HTTP/DNS/TLS) for blind SSRF, XXE, and injection detection
- **Traffic Proxy** — mitmproxy-based interceptor with rule-based request/response manipulation
- **Sandbox Payload Engine** — WAF fingerprinting + mutation engine generates per-context payload variants with chain depth control
- **Structured Reporting** — PDF and Markdown report generation with vulnerability deduplication, remediation mapping, and LLM-assisted write-up
- **Bounty Tracker** — Tracks submissions to bug bounty platforms with payout estimation and ROI stats
- **Scheduled Rescans** — Cron-based recurring scans with asset snapshotting and diff detection for new/disappeared assets
- **Monitoring Stack** — Optional Prometheus + Grafana + Loki + cAdvisor overlay for container and queue metrics

## Architecture

```
┌────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Dashboard    │────▶│   Orchestrator   │────▶│  Redis Streams   │
│   (Next.js)    │◀─SSE│   (FastAPI)      │     │  (Message Broker)│
└────────────────┘     └────────┬─────────┘     └────────┬─────────┘
                                │                        │
                         ┌──────▼──────┐         ┌──────▼──────────┐
                         │  PostgreSQL │◀─────────│  Docker Workers │
                         │  (24 tables)│          │  (20+ services) │
                         └─────────────┘          └─────────────────┘
                                        ┌──────────────┐
                                        │    Ollama    │
                                        │  (local LLM) │
                                        └──────────────┘
```

**Data Flow:** Target submitted via dashboard → orchestrator writes profile + pushes task to Redis → worker picks up message via consumer group → runs staged pipeline → results written to PostgreSQL → SSE events streamed to dashboard in real time → reasoning worker enriches findings with LLM analysis → chain worker discovers multi-step attack paths → reporting worker generates final report.

## Technologies

| Layer | Stack |
|-------|-------|
| **Orchestrator** | Python 3.10, FastAPI, Uvicorn, Docker SDK, SSE |
| **Database** | PostgreSQL 15, SQLAlchemy 2.0 (async), asyncpg |
| **Messaging** | Redis 7 (Streams + consumer groups, priority queuing) |
| **Dashboard** | Next.js 16, React 19, TypeScript, Tailwind CSS v4, Zustand, TanStack Table |
| **Workers** | Python (async), Playwright, mitmproxy, multi-stage Docker builds |
| **LLM** | Ollama (local inference), Qwen3:14b default, configurable model |
| **Infrastructure** | Docker Compose, bridge network, health checks, resource limits |
| **Monitoring** | Prometheus, Grafana, Loki, Promtail, cAdvisor, node-exporter |

## Workers

Workers are organized by OWASP WSTG section. Each follows the same pattern: `base_tool.py` → `tools/` → `pipeline.py` → `concurrency.py` → `main.py`.

| Worker | Purpose | Key Capabilities |
|--------|---------|-----------------|
| **info-gathering** | Passive + active information collection | WHOIS, DNS, subdomain enumeration, fingerprinting, port mapping, subdomain takeover detection |
| **identity-mgmt** | Identity and account enumeration | User enumeration, account lockout, role mapping |
| **authentication** | Authentication mechanism testing | Credential brute-force, password policy, MFA bypass, token analysis |
| **authorization** | Access control testing | IDOR, privilege escalation, horizontal/vertical access control |
| **session-mgmt** | Session security analysis | Cookie flags, session fixation, CSRF, token predictability |
| **input-validation** | Injection and input-based vulnerabilities | SQLi, XSS, XXE, SSRF, SSTI, command injection, path traversal |
| **error-handling** | Error disclosure and stack trace detection | Verbose error fingerprinting, debug endpoint discovery |
| **cryptography** | TLS/SSL and algorithm auditing | TLS version/cipher, padding oracle, plaintext leak scanner |
| **business-logic** | Business logic flaw detection | Race conditions, workflow bypass, price manipulation |
| **client-side** | Browser-based client-side testing | DOM XSS, postMessage abuse, CSP bypass (Playwright) |
| **chain-worker** | Multi-step exploit chaining | Correlates escalation contexts, builds attack chains, feeds reporting |
| **reporting-worker** | Report generation | PDF + Markdown, vulnerability deduplication, remediation mapping, LLM write-up |
| **reasoning-worker** | LLM vulnerability analysis | 10-dimension insight enrichment via local Ollama |
| **sandbox-worker** | Payload mutation engine | WAF fingerprinting, per-context payload variants, mutation outcome tracking |
| **proxy** | Traffic interception | mitmproxy addon with rule-based request/response manipulation |
| **callback** | OOB interaction listener | HTTP/DNS/TLS listeners for blind vulnerability confirmation |
| **mobile-worker** | Mobile app SAST + DAST | MobSF static analysis, Frida dynamic instrumentation, docker-android emulator |

## Quick Start

```bash
git clone <repo-url> && cd WebAppBH
docker compose up --build
```

Dashboard: `http://localhost:3000` — API: `http://localhost:8001`

MobSF (mobile analysis sidecar): `http://localhost:8000`

## Run Individual Services

```bash
# Infrastructure only
docker compose up postgres redis

# Orchestrator API
docker compose up orchestrator

# Dashboard
docker compose up dashboard

# Specific worker
docker compose up info-gathering
docker compose up chain-worker
docker compose up reasoning-worker

# Mobile stack (requires KVM support)
docker compose up mobile-worker mobsf docker-android
```

## Development

```bash
# Install shared library (editable)
pip install -e shared/lib_webbh
pip install -e "shared/lib_webbh[dev]"    # includes pytest, pytest-asyncio, aiosqlite

# Dashboard
cd dashboard && npm install && npm run dev

# Run tests
pytest                                     # all tests
pytest tests/test_scope.py                 # single file
pytest tests/test_recon_tools_passive.py -k "test_subfinder"  # single test
```

Tests use `anyio_backend = "asyncio"` and an in-memory aiosqlite database. Orchestrator-specific fixtures are in `tests/conftest_orchestrator.py`.

## API

All endpoints are prefixed with `/api/v1/` and require an `X-API-KEY` header.

```bash
# Create a target
curl -X POST http://localhost:8001/api/v1/targets \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"company_name": "Example Corp", "base_domain": "example.com"}'

# Apply a scan playbook
curl -X POST http://localhost:8001/api/v1/targets/1/apply-playbook \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"playbook": "wide_recon"}'

# List vulnerabilities for a target
curl "http://localhost:8001/api/v1/vulnerabilities?target_id=1" \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY"

# Fetch attack graph
curl http://localhost:8001/api/v1/targets/1/graph \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY"

# Stream real-time events (SSE)
curl http://localhost:8001/api/v1/stream/1 \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY"

# Trigger report generation
curl -X POST http://localhost:8001/api/v1/targets/1/reports \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY"

# Track a bounty submission
curl -X POST http://localhost:8001/api/v1/bounties \
  -H "X-API-KEY: $WEB_APP_BH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1, "vulnerability_id": 5, "platform": "hackerone", "status": "submitted"}'
```

### Full API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/targets` | Create a new scan target |
| `GET` | `/api/v1/targets` | List all targets |
| `PATCH` | `/api/v1/targets/{id}` | Update target profile |
| `DELETE` | `/api/v1/targets/{id}` | Delete a target |
| `POST` | `/api/v1/targets/{id}/apply-playbook` | Apply a scan playbook |
| `POST` | `/api/v1/targets/{id}/rescan` | Snapshot assets and queue rescan |
| `GET` | `/api/v1/targets/{id}/graph` | Attack graph (nodes + edges) |
| `GET` | `/api/v1/targets/{id}/attack-paths` | Exploitable vuln chains by asset |
| `GET` | `/api/v1/targets/{id}/correlations` | Correlated vulnerability groups |
| `GET` | `/api/v1/targets/{id}/execution` | Pipeline execution state |
| `POST` | `/api/v1/targets/{id}/reports` | Trigger report generation |
| `GET` | `/api/v1/targets/{id}/reports` | List generated reports |
| `GET` | `/api/v1/targets/{id}/reports/{filename}` | Download a report |
| `GET` | `/api/v1/assets` | List assets for a target |
| `GET` | `/api/v1/assets/{id}/locations` | Network locations for an asset |
| `GET` | `/api/v1/assets/{id}/vulnerabilities` | Vulnerabilities for an asset |
| `GET` | `/api/v1/vulnerabilities` | List vulnerabilities for a target |
| `GET` | `/api/v1/vulnerabilities/{id}/draft` | Draft vuln report for platform |
| `GET` | `/api/v1/cloud_assets` | List cloud assets |
| `GET` | `/api/v1/alerts` | List alerts |
| `PATCH` | `/api/v1/alerts/{id}` | Mark alert read |
| `GET` | `/api/v1/status` | Real-time job states |
| `POST` | `/api/v1/control` | Pause / stop / restart workers |
| `POST` | `/api/v1/kill` | Hard-kill all active workers |
| `GET` | `/api/v1/stream/{target_id}` | SSE event stream per target |
| `GET` | `/api/v1/queue_health` | Queue depth health |
| `GET` | `/api/v1/search` | Global search across assets and vulns |
| `POST` | `/api/v1/bounties` | Create bounty submission |
| `GET` | `/api/v1/bounties` | List bounty submissions |
| `PATCH` | `/api/v1/bounties/{id}` | Update bounty submission |
| `GET` | `/api/v1/bounties/stats` | Bounty ROI stats |

## Scan Playbooks

| Playbook | Description |
|----------|-------------|
| `wide_recon` | Full 7-stage pipeline, high concurrency. Best for large targets. |
| `deep_webapp` | Skips active discovery and takeover checks; emphasizes fingerprinting and deep recon. |
| `api_focused` | Minimal recon, maximum parameter discovery. For targets with a known API surface. |
| `cloud_first` | Full recon plus aggressive cloud enumeration. |

Custom playbooks can be created via the API and stored in the database.

## Environment Variables

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
| `LLM_BASE_URL` | `http://ollama:11434` | Ollama API base URL |
| `LLM_MODEL` | `qwen3:14b` | LLM model for reasoning worker |
| `SHODAN_API_KEY` | — | Optional Shodan enrichment |
| `SECURITYTRAILS_API_KEY` | — | Optional SecurityTrails enrichment |
| `MOBSF_API_KEY` | — | MobSF API key for mobile analysis |

## Monitoring

An optional observability stack can be overlaid on the main compose file:

```bash
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up
```

| Service | Port | Purpose |
|---------|------|---------|
| Prometheus | 9090 | Metrics scraping and storage |
| Grafana | 3001 | Dashboards and alerting |
| Loki + Promtail | — | Log aggregation |
| cAdvisor | 8080 | Container resource metrics |
| node-exporter | — | Host metrics |

## Project Structure

```
WebAppBH/
├── shared/
│   ├── lib_webbh/          # Core library (DB models, messaging, scope, logging, LLM client, playbooks)
│   └── schema.sql          # PostgreSQL schema (24 tables)
├── orchestrator/           # FastAPI control plane, event engine, worker manager
├── workers/
│   ├── info_gathering/     # passive + active recon
│   ├── identity_mgmt/      # identity enumeration
│   ├── authentication/     # auth mechanism testing
│   ├── authorization/      # access control testing
│   ├── session_mgmt/       # session security
│   ├── input_validation/   # injection testing
│   ├── error_handling/     # error disclosure
│   ├── cryptography/       # TLS/crypto auditing
│   ├── business_logic/     # business logic flaws
│   ├── client_side/        # browser/DOM testing
│   ├── chain_worker/       # Exploit chain discovery
│   ├── reporting_worker/   # PDF + Markdown report generation
│   ├── reasoning_worker/   # LLM vulnerability analysis (Ollama)
│   ├── sandbox_worker/     # Payload mutation engine
│   ├── proxy/              # mitmproxy traffic interceptor
│   ├── callback/           # OOB interaction listener
│   └── mobile_worker/      # Mobile SAST + DAST (MobSF + Frida)
├── dashboard/              # Next.js 16 C2 interface
├── docker/                 # One Dockerfile per service
├── monitoring/             # Prometheus, Grafana, Loki, Promtail config
├── scripts/                # DB backup/restore, migration helpers
├── tests/                  # Pytest test suite (unit + integration + e2e)
└── docs/plans/             # Phase specs, design docs, implementation plans
```

## Database Schema

The shared library defines 24 SQLAlchemy models covering the full engagement lifecycle:

`campaigns` → `targets` → `assets` → `locations` / `observations` / `parameters`

`vulnerabilities` → `alerts` / `bounty_submissions` / `escalation_contexts` / `chain_findings` / `vulnerability_insights`

`job_state` · `api_schemas` · `mobile_apps` · `cloud_assets` · `identities`

`asset_snapshots` · `scope_violations` · `custom_playbooks` · `scheduled_scans`

`tool_hit_rates` · `mutation_outcomes`
