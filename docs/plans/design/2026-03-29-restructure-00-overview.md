# WSTG-Aligned Restructure — 00 Architecture Overview

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Scope:** Full restructure of workers, pipelines, orchestrator, database, dashboard, and reporting to align with OWASP WSTG v4 testing methodology.

---

## Motivation

The current worker architecture is organized by **tool capability** (recon, fuzzing, webapp, vuln scanning). The OWASP Web Security Testing Guide v4 organizes testing by **security domain** (information gathering, configuration management, authentication, session management, etc.). This mismatch creates several problems:

1. **Testing coverage gaps** — Identity management (4.3), error handling (4.8), cryptography (4.9), and business logic (4.10) have minimal or no dedicated coverage.
2. **Scattered responsibilities** — Authentication testing is split across api_worker (JWT, OAuth), network_worker (default credentials), and webapp_worker (cookie checks) with no unified ownership.
3. **Nuclei as triage router** — The vuln_scanner uses Nuclei templates to decide which active tools to run. This misses novel variants that Nuclei templates don't cover. Purpose-built tools running against all entry points are more thorough.
4. **No WSTG traceability** — Findings cannot be mapped back to specific WSTG test sections, making it difficult to demonstrate testing completeness to program managers or compliance auditors.

## New Architecture

### Worker Inventory

14 total workers: 11 WSTG-aligned core workers + 3 extension workers.

| Worker | Directory | Section | Pipeline Stages | Queue |
|--------|-----------|---------|----------------|-------|
| Info Gathering | `workers/info_gathering/` | 4.1 | 10 | `info_gathering_queue` |
| Config Management | `workers/config_mgmt/` | 4.2 | 11 | `config_mgmt_queue` |
| Identity Management | `workers/identity_mgmt/` | 4.3 | 5 | `identity_mgmt_queue` |
| Authentication | `workers/authentication/` | 4.4 | 10 | `authentication_queue` |
| Authorization | `workers/authorization/` | 4.5 | 4 | `authorization_queue` |
| Session Management | `workers/session_mgmt/` | 4.6 | 9 | `session_mgmt_queue` |
| Input Validation | `workers/input_validation/` | 4.7 | 15 | `input_validation_queue` |
| Error Handling | `workers/error_handling/` | 4.8 | 2 | `error_handling_queue` |
| Cryptography | `workers/cryptography/` | 4.9 | 4 | `cryptography_queue` |
| Business Logic | `workers/business_logic/` | 4.10 | 9 | `business_logic_queue` |
| Client-Side | `workers/client_side/` | 4.11 | 13 | `client_side_queue` |
| Mobile | `workers/mobile/` | Extension | Unchanged | `mobile_queue` |
| Chain | `workers/chain/` | Extension | Updated | `chain_queue` |
| Reporting | `workers/reporting/` | Extension | Updated | `reporting_queue` |

### Infrastructure Services

Two new Docker services added alongside existing infrastructure:

| Service | Purpose | Container |
|---------|---------|-----------|
| Traffic Proxy | Opt-in mitmproxy-based HTTP interception for request/response manipulation | `proxy` |
| Callback Server | Self-hosted OOB listener for blind injection, DNS callbacks, reverse shell catch | `callback` |

Details in `restructure-01-infrastructure-services.md`.

### Worker File Structure

Every worker follows the existing pattern:

```
workers/{name}/
├── main.py           # Entry point, queue listener
├── base_tool.py      # Abstract base class for this worker's tools
├── pipeline.py       # Ordered stage list, checkpoint logic
├── concurrency.py    # Semaphore pools (HEAVY/LIGHT)
└── tools/            # One file per tool, subclasses base_tool
    ├── tool_a.py
    ├── tool_b.py
    └── ...
```

### Dependency Graph

Workers fire based on dependency completion, not sequential ordering. Three parallel branches run after info_gathering, converging at business_logic.

```
                        ┌─── TARGET CREATED ───┐
                        │                      │
                        ▼                      │
                  info_gathering               │
                        │                      │
           ┌────────────┼────────────┐         │
           ▼            ▼            ▼         │
      config_mgmt  input_validation  client_side
           │            │            │
           ├────┐       │            │
           ▼    ▼       ▼            │
    cryptography identity_mgmt  error_handling
                    │
                    ▼
              authentication
                 │      │
                 ▼      ▼
          authorization  session_mgmt
                 │      │
                 └──┬───┘
                    ▼
              business_logic
                    │
                    ▼
                  chain
                    │
                    ▼
                reporting
```

Mobile worker runs independently — triggered by mobile app records, not part of the WSTG chain.

### Trigger Conditions

| Worker | Fires When |
|--------|-----------|
| info_gathering | Target created |
| config_mgmt | info_gathering complete |
| input_validation | info_gathering complete |
| client_side | info_gathering complete |
| cryptography | config_mgmt complete |
| identity_mgmt | config_mgmt complete |
| error_handling | input_validation complete |
| authentication | identity_mgmt complete |
| authorization | authentication complete |
| session_mgmt | authentication complete |
| business_logic | authorization AND session_mgmt complete |
| chain | All 11 WSTG workers complete |
| reporting | chain complete |
| mobile | Mobile app record found (independent) |

Details in `restructure-09-orchestrator.md`.

### Target Expansion

After info_gathering completes, a `TargetExpander` component collects all in-scope URLs:
- Original seed URLs from campaign creation
- Active subdomains discovered
- VHost URLs discovered
- Live URLs from execution path mapping

Each becomes a child Target record that runs through the full WSTG pipeline independently. A prioritized queue with resource guard tiers controls throughput to prevent infrastructure starvation.

Details in `restructure-08-target-expansion-resources.md`.

## Tool Redistribution

### Old Workers Dissolved

| Old Worker | Status | Tools Redistributed To |
|-----------|--------|----------------------|
| recon_core | Dissolved | info_gathering, config_mgmt |
| webapp_worker | Dissolved | info_gathering, config_mgmt, session_mgmt, input_validation, client_side |
| fuzzing_worker | Dissolved | config_mgmt, input_validation, client_side |
| api_worker | Dissolved | authentication, authorization, input_validation, business_logic |
| vuln_scanner | Dissolved | input_validation |
| cloud_worker | Dissolved | config_mgmt stage 11 |
| network_worker | Dissolved | config_mgmt, authentication, input_validation |

### Retired Tools

| Retired Tool | Reason | Absorbed By |
|-------------|--------|-------------|
| Gauplus | Redundant sources | Waybackurls (extended with OTX, Common Crawl, URLScan) |
| Chaos | Subfinder already queries it | Subfinder |
| Knockpy | DNS brute-force redundant | AmassActive + Subfinder |
| NucleiTool | WSTG structure replaces triage routing | Each injection type tested directly per stage |

### Tool Counts

| Worker | Carried Forward | New Tools | Total |
|--------|----------------|-----------|-------|
| info_gathering | 10 | 7 | 17 |
| config_mgmt | 5 | 14 | 19 |
| identity_mgmt | 0 | 5 | 5 |
| authentication | 2 | 10 | 12 |
| authorization | 2 | 3 | 5 |
| session_mgmt | 1 | 8 | 9 |
| input_validation | 11 | 10 | 21 |
| error_handling | 0 | 2 | 2 |
| cryptography | 0 | 4 | 4 |
| business_logic | 1 | 8 | 9 |
| client_side | 6 | 7 | 13 |
| **Total** | **38** | **78** | **116** |

## Safety Policy

Two credential pairs per campaign (Tester Credentials + Testing User). Strict targeting rules: only Tester session for authenticated testing, only Testing User as permitted victim. Real users documented but never acted upon. Escalated access is read-only — documented and passed to the chain worker.

Details in `restructure-02-safety-policy.md`.

## Document Index

| Document | Contents |
|----------|----------|
| `restructure-00-overview.md` | This document — architecture summary, worker inventory, tool redistribution |
| `restructure-01-infrastructure-services.md` | Traffic proxy and callback server design |
| `restructure-02-safety-policy.md` | Credential policy, targeting rules, escalated access handling |
| `restructure-03-info-gathering.md` | Info Gathering worker — 10 stages, all tools |
| `restructure-04-config-mgmt.md` | Config Management worker — 11 stages, cloud/network absorption |
| `restructure-05-identity-auth-authz-session.md` | Identity, Authentication, Authorization, Session workers — 28 stages |
| `restructure-06-input-validation.md` | Input Validation worker — 15 stages, DB-specific routing |
| `restructure-07-error-crypto-logic-client.md` | Error Handling, Cryptography, Business Logic, Client-Side workers — 28 stages |
| `restructure-08-target-expansion-resources.md` | TargetExpander, priority queue, resource guard tiers |
| `restructure-09-orchestrator.md` | Event engine rewrite, dependency map, poll cycle |
| `restructure-10-database-messaging.md` | Schema changes, new tables, Redis stream names |
| `restructure-11-dashboard-reporting.md` | Dashboard UI changes, bug submission report format |
| `restructure-12-migration.md` | Phased implementation plan, backward compatibility |
