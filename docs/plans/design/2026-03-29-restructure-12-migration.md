# WSTG-Aligned Restructure — 12 Migration Path

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** All previous documents
**Scope:** Phased implementation order, backward compatibility, cutover strategy

---

## Overview

This document defines the implementation order for the restructured framework. The migration is broken into sequential implementation phases that can each be validated independently before moving to the next. Each phase produces working code — there is no "big bang" cutover.

---

## Implementation Phases

### Phase M1: Shared Library & Database Schema

**Goal:** Update `lib_webbh` with new models, columns, tables, and messaging helpers. All downstream code depends on this.

**Changes:**
1. Add new columns to `Target` model (parent_target_id, target_type, priority, wildcard, wildcard_count, campaign_id)
2. Add new columns to `Vulnerability` model (section_id, worker_type, stage_name, source_tool, title, evidence, remediation, false_positive)
3. Add new columns to `JobState` model (current_section_id, skipped, skip_reason, queued_at, started_at, completed_at, retry_count)
4. Create `Campaign` model
5. Create `EscalationContext` model
6. Create `ChainFinding` model
7. Create all new indexes
8. Add `push_priority_task()` and `listen_priority_queues()` to `messaging.py`
9. Generate and apply Alembic migration
10. Update test fixtures to use new schema

**Validation:** All existing tests pass. New models can be created and queried. Priority queue functions work with Redis.

**Dependencies:** None — this is the foundation.

---

### Phase M2: Infrastructure Services

**Goal:** Stand up the Traffic Proxy and Callback Server as Docker containers.

**Changes:**
1. Create `docker/Dockerfile.proxy` — mitmproxy + Rule Manager REST API
2. Create `docker/Dockerfile.callback` — HTTP/DNS/TCP listener + polling API
3. Create `workers/proxy/` directory with rule_manager.py and mitmproxy addon
4. Create `workers/callback/` directory with listeners and callback store
5. Add both services to `docker-compose.yml` with proper networking
6. Add proxy and callback helper methods to a shared base mixin (for use in worker base_tool classes)
7. Write integration tests: proxy forwards requests, rules modify traffic, callbacks register and fire

**Validation:** `docker compose up proxy callback` starts both services. Rule Manager API accepts rules. Callback server registers and receives callbacks.

**Dependencies:** None — runs independently.

---

### Phase M3: Orchestrator Event Engine

**Goal:** Replace the sequential phase-based orchestrator with the dependency-driven event engine.

**Changes:**
1. Create `orchestrator/dependency_map.py` with DEPENDENCY_MAP and resolve_effective_dependencies()
2. Create `orchestrator/event_engine.py` with poll cycle, dependency evaluation, worker dispatch
3. Create `orchestrator/resource_guard.py` with tier evaluation, threshold configuration, API endpoints
4. Create `orchestrator/target_expander.py` with expansion logic, deduplication, priority scoring
5. Update `orchestrator/worker_manager.py` for new worker types and container lifecycle
6. Add campaign management API endpoints (create, start, pause, resume, cancel)
7. Add resource guard API endpoints (status, override, thresholds)
8. Update SSE event stream to include new event types
9. Write tests for dependency resolution (with and without credentials), resource guard tiers, target expansion

**Validation:** Create a campaign via API. Event engine correctly sequences workers based on dependencies. Resource guard responds to CPU/memory thresholds. Target expansion creates child targets with correct priorities.

**Dependencies:** Phase M1 (new database models).

---

### Phase M4: Info Gathering Worker (Restructured)

**Goal:** Restructure the existing recon_core worker into the new info_gathering worker with 10 WSTG-aligned stages.

**Changes:**
1. Create `workers/info_gathering/` directory structure (base_tool.py, pipeline.py, concurrency.py, tools/)
2. Migrate existing tools: Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns, Httpx, Nmap, WhatWeb, Katana, Hakrawler, Paramspider, Waybackurls, Naabu, Wappalyzer, Webanalyze, CommentHarvester
3. Create new tools: DorkEngine, ArchiveProber, MetafileParser, VHostProber, MetadataExtractor, FormMapper, CookieFingerprinter, ArchitectureModeler
4. Extend Waybackurls to absorb Gauplus capabilities (multiple archive sources)
5. Extend AmassActive to absorb Knockpy capabilities (zone transfer, brute force)
6. Wire pipeline stages to WSTG 4.1.1 through 4.1.10
7. Create `docker/Dockerfile.info_gathering`
8. Add to docker-compose.yml
9. Write tests for each new tool and the overall pipeline

**Validation:** `docker compose up worker_info_gathering` starts. Pipeline runs all 10 stages in order. All carried-forward tools produce output. New tools function correctly. Assets written to DB with correct types.

**Dependencies:** Phase M1, Phase M3 (event engine dispatches to this worker).

---

### Phase M5: Config Management Worker

**Goal:** Build the config_mgmt worker covering WSTG 4.2, absorbing cloud_worker and parts of network_worker and fuzzing_worker.

**Changes:**
1. Create `workers/config_mgmt/` directory structure
2. Migrate relevant tools from existing workers (Ffuf for file discovery, cloud tools)
3. Create new tools: NetworkConfigTester, PlatformFingerprinter, FileExtensionTester, BackupFileFinder, ApiDiscoveryTool, HttpMethodTester, HstsTester, RpcTester, FileInclusionTester, SubdomainTakeoverChecker, CloudStorageAuditor
4. Wire pipeline stages to WSTG 4.2.1 through 4.2.11
5. Create Dockerfile and docker-compose entry
6. Write tests

**Validation:** Pipeline runs 11 stages. Cloud testing absorbed correctly. Subdomain takeover detection works. Config findings written to DB.

**Dependencies:** Phase M1, Phase M4 (needs info_gathering output).

---

### Phase M6: Identity, Auth, AuthZ, Session Workers

**Goal:** Build the four credential-dependent workers. These are all new — no existing workers to migrate.

**Changes:**
1. Create `workers/identity_mgmt/` — 5 stages (WSTG 4.3)
2. Create `workers/authentication/` — 10 stages (WSTG 4.4)
3. Create `workers/authorization/` — 4 stages (WSTG 4.5)
4. Create `workers/session_mgmt/` — 9 stages (WSTG 4.6)
5. Implement credential management: loading credentials.json, Tester session authentication, Testing User identification
6. Implement safety policy enforcement in base_tool classes
7. Implement escalated access handling (on_escalated_access, session data encryption)
8. Implement skip logic for no-credential campaigns
9. Create Dockerfiles and docker-compose entries
10. Write tests (with and without credentials, safety policy enforcement)

**Validation:** With credentials: all four workers run their full pipelines. Without credentials: all four are skipped with correct status. Tester session authenticates successfully. Testing User is used as victim without credential usage. Escalated access is documented but not exploited.

**Dependencies:** Phase M1, Phase M5 (needs config_mgmt output).

---

### Phase M7: Input Validation Worker

**Goal:** Build the largest worker covering WSTG 4.7, absorbing tools from vuln_scanner, fuzzing_worker, webapp_worker, api_worker.

**Changes:**
1. Create `workers/input_validation/` — 15 stages (WSTG 4.7.1 through 4.7.19)
2. Migrate existing tools: Sqlmap, Ffuf (parameter fuzzing), XSS detection tools, SSRF tools
3. Create new tools: ReflectedXssTester, StoredXssTester, HttpVerbTamperTester, HttpParameterPollutionTester, SqlmapGenericTool, SqlmapOracleTool (config variant), SqlmapMssqlTool (config variant), SqlmapPostgresTool (config variant), LdapInjectionTester, XmlInjectionTester, SstiTester, XpathInjectionTester, ImapSmtpInjectionTester, CodeInjectionTester, CommandInjectionTester, FormatStringTester, HostHeaderTester, SsrfTester, LocalFileInclusionTester, RemoteFileInclusionTester, BufferOverflowTester, IncubatedVulnTester, HttpSmugglingTester, WebSocketInjectionTester
4. Integrate with callback server for blind injection detection
5. Integrate with traffic proxy for request manipulation
6. Create Dockerfile and docker-compose entry
7. Write tests for each injection type

**Validation:** Pipeline runs 15 stages. Each injection tool produces findings against vulnerable test targets. Callback server detects blind injection. Proxy captures and modifies requests.

**Dependencies:** Phase M1, Phase M2 (proxy + callback), Phase M6 (needs auth context).

---

### Phase M8: Error Handling, Cryptography, Business Logic, Client-Side Workers

**Goal:** Build the four workers that run in parallel after input_validation completes (or after config_mgmt for error_handling, cryptography, and client_side).

**Changes:**
1. Create `workers/error_handling/` — 2 stages (WSTG 4.8)
2. Create `workers/cryptography/` — 4 stages (WSTG 4.9)
3. Create `workers/business_logic/` — 9 stages (WSTG 4.10)
4. Create `workers/client_side/` — 13 stages (WSTG 4.11)
5. Implement BrowserManager singleton for client_side worker (Playwright Chromium)
6. Integrate with callback server (css_injection, resource_manipulation, malicious_upload)
7. Integrate with traffic proxy (request_forgery, integrity_checks, dom_xss)
8. Create Dockerfiles and docker-compose entries
9. Write tests

**Validation:** All four workers run their pipelines. BrowserManager provides isolated browser contexts. Client-side DOM analysis detects test vulnerabilities. Business logic race condition detection works.

**Dependencies:** Phase M1, Phase M2, Phase M5/M6 (dependency varies per worker).

---

### Phase M9: Chain Worker & Reporting Worker

**Goal:** Build the chain_worker (vulnerability chaining using escalation contexts) and reporting worker (bug submission reports).

**Changes:**
1. Create `workers/chain_worker/` — consumes EscalationContext records, probes for further access, creates ChainFinding records
2. Create `workers/reporting/` — generates individual bug reports and chain reports as Markdown
3. Implement report storage in `shared/reports/{campaign_id}/{target_domain}/`
4. Create Dockerfiles and docker-compose entries
5. Write tests

**Validation:** Chain worker reads escalation contexts, identifies chains, stores chain findings. Reporting worker produces correctly formatted Markdown reports. Reports contain all required sections for bug bounty submission.

**Dependencies:** Phase M1, Phase M8 (needs findings from all testing workers).

---

### Phase M10: Dashboard Updates

**Goal:** Update the Next.js dashboard with all new views.

**Changes:**
1. Campaign creator form with credential management
2. Pipeline progress grid with dependency-aware layout
3. Worker detail drawer with stage progress
4. Target hierarchy view (seed → child tree)
5. Resource guard indicator and management panel
6. Findings table with section_id-based filtering
7. Finding detail view with evidence display
8. Chain findings view
9. Report list and individual report display
10. Report export (download individual, download all as ZIP, copy to clipboard)
11. Live terminal with SSE event stream
12. Update Zustand stores for new data shapes
13. Update SSE hook for new event types

**Validation:** Campaign can be created via the UI. Pipeline grid updates in real-time via SSE. Target hierarchy displays correctly. Findings filter by section_id. Reports render and export properly.

**Dependencies:** Phase M3 (API endpoints), Phase M9 (reporting data).

---

### Phase M11: Cleanup & Retirement

**Goal:** Remove old worker code, old Docker configurations, old Redis streams.

**Changes:**
1. Remove `workers/recon_core/` (replaced by info_gathering)
2. Remove `workers/network_worker/` (absorbed by config_mgmt)
3. Remove `workers/fuzzing_worker/` (absorbed by config_mgmt + input_validation)
4. Remove `workers/cloud_worker/` (absorbed by config_mgmt)
5. Remove `workers/webapp_worker/` (absorbed by input_validation)
6. Remove `workers/api_worker/` (absorbed by input_validation)
7. Remove `workers/vuln_scanner/` (absorbed by input_validation)
8. Remove old Dockerfiles for retired workers
9. Remove old docker-compose entries
10. Run Redis stream cleanup (drain and delete old streams)
11. Remove Nuclei and its configuration (WSTG structure replaces its routing role)
12. Remove Gauplus, Chaos, Knockpy binaries/configs
13. Update CLAUDE.md with new architecture documentation

**Validation:** `docker compose up --build` starts all new workers. No references to old worker names in codebase. Old Redis streams deleted. All tests pass.

**Dependencies:** All previous phases complete and validated.

---

## Phase Dependency Graph

```
M1 (Shared Library + DB)
├── M2 (Infrastructure Services) ← independent of M1
├── M3 (Orchestrator)
│   └── M4 (Info Gathering)
│       └── M5 (Config Mgmt)
│           └── M6 (Identity/Auth/AuthZ/Session)
│               └── M7 (Input Validation) ← also depends on M2
│                   └── M8 (Error/Crypto/Logic/Client) ← also depends on M2
│                       └── M9 (Chain + Reporting)
│                           └── M10 (Dashboard)
│                               └── M11 (Cleanup)
```

M1 and M2 can be implemented in parallel. Everything else is sequential.

---

## Backward Compatibility

### During Migration

While both old and new workers coexist:
- The event engine checks `worker_type` against both old and new names
- Old Redis streams remain active until M11
- Database columns added with nullable defaults — existing data is unaffected
- The dashboard detects which worker types exist and renders accordingly

### Data Migration

- Existing Target records get `target_type = "seed"` and `campaign_id` pointing to a "Legacy Campaign" record
- Existing JobState records get `worker_type` remapped from old names to new names
- Existing Vulnerability records gain new nullable columns — section_id and worker_type are populated during migration where mappable

### Rollback Strategy

Each phase has its own Alembic migration with a downgrade path. To roll back:
1. Stop new worker containers
2. Run `alembic downgrade` for the relevant migration
3. Restart old worker containers
4. Old Redis streams are preserved until M11

After M11 (cleanup), rollback requires restoring from backup.

---

## Estimated Scope per Phase

| Phase | New Files | Modified Files | New Tools | Tests |
|-------|-----------|---------------|-----------|-------|
| M1 | 2 | 4 | 0 | 15 |
| M2 | 8 | 2 | 0 | 10 |
| M3 | 5 | 3 | 0 | 20 |
| M4 | 30 | 2 | 8 | 25 |
| M5 | 20 | 1 | 11 | 20 |
| M6 | 40 | 2 | 28 | 35 |
| M7 | 30 | 1 | 24 | 30 |
| M8 | 45 | 2 | 28 | 40 |
| M9 | 10 | 1 | 2 | 15 |
| M10 | 20 | 10 | 0 | 10 |
| M11 | 0 | 5 | 0 | 5 |
| **Total** | **~210** | **~33** | **~101** | **~225** |

---

## Testing Strategy

### Per-Phase Testing

Each phase includes:
1. **Unit tests** for new functions and classes (pytest, in-memory SQLite via aiosqlite)
2. **Integration tests** for worker pipelines (run against test targets with known vulnerabilities)
3. **Dependency tests** for event engine (verify correct sequencing)

### End-to-End Testing

After M9, run a full campaign against a controlled test environment (DVWA, WebGoat, or similar) to validate:
- All workers fire in correct order
- Target expansion creates children
- Resource guard throttles appropriately
- Findings are stored with correct section_ids
- Chain worker identifies vulnerability chains
- Reports are generated with correct format

### Regression Testing

Throughout migration, the existing test suite must continue to pass. New tests are added alongside, never replacing existing tests until M11 (cleanup).
