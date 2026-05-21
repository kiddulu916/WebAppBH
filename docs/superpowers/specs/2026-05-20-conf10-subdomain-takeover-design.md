# WSTG-CONF-10: Subdomain Takeover Tester — Design Spec

**Date:** 2026-05-20  
**WSTG reference:** WSTG-CONF-10 — Test for Subdomain Takeover  
**Worker:** `config_mgmt`  
**Stage:** `subdomain_takeover` (position 13 in pipeline, already wired)

---

## Context

The `subdomain_takeover` pipeline stage and `SubdomainTakeoverChecker` class already exist in `workers/config_mgmt/tools/subdomain_takeover_checker.py`, but the current implementation is a low-quality stub using the old inline-Python-subprocess pattern (`build_command` returns `python3 -c <script>`). All three coherence layers are already correctly wired:

- `pipeline.py` — `Stage("subdomain_takeover", [SubdomainTakeoverChecker])`
- `playbooks.py` — `"subdomain_takeover"` present in `PIPELINE_STAGES`
- `worker-stages.ts` — `{ stageName: "subdomain_takeover", sectionId: "WSTG-CONF-10" }`
- `concurrency.py` — `"subdomain_takeover_checker": WeightClass.LIGHT`

**No changes are needed to any of these files.** The entire work is a rewrite of `subdomain_takeover_checker.py`, Dockerfile additions, copying curated nuclei templates into the project, and new unit tests.

---

## Objectives (from OWASP WSTG-CONF-10)

1. Enumerate all possible subdomains (current and forgotten).
2. Identify DNS records pointing to inactive or unclaimed third-party services (dangling CNAMEs, expired NS delegations).
3. Confirm takeover possibility via HTTP fingerprinting.

---

## Approach: subjack → nuclei (triage then verify)

**Phase 1 — Subdomain assembly**  
Collect subdomains from two sources:
- Query the `Asset` table for this `target_id` where `asset_type IN ('subdomain', 'url', 'domain', 'ip')` — uses work already done by earlier pipeline stages.
- Generate `<prefix>.<target_domain>` for each entry in a ~200-entry common-prefix wordlist (www, api, dev, staging, mail, cdn, app, admin, …).

Deduplicate and write to a temp file.

**Phase 2 — subjack (fast CNAME fingerprinting)**  
Run `subjack` against the full subdomain list. subjack resolves each subdomain's CNAME chain and checks it against ~50 built-in service fingerprints. It is fast (parallel, Go), making it suitable for wide-net screening.

- `[Vulnerable]` entries (confirmed unclaimed resource) → `severity: critical`
- CNAME-dangling entries (points to known service, unresolved) → `severity: high`
- All subjack hits are collected as "suspects" for Phase 3.

**Phase 3 — nuclei (deep HTTP fingerprinting on suspects)**  
Run `nuclei` only against the suspects identified in Phase 2. This limits nuclei's template execution to the subdomains that already showed signs of vulnerability, keeping runtime bounded.

Template sources (both used):
- `/nuclei-templates/custom/` — curated takeover templates from `workers/config_mgmt/nuclei-templates/` (copied from `Custom-Nuclei-Templates/takeovers/` at build time)
- `/nuclei-templates/community/http/takeovers/` — nuclei community templates fetched via `nuclei -update-templates` at Docker build time

All confirmed nuclei matches → `severity: critical`; nuclei `medium` findings → `severity: high`.

---

## Component Design

### `workers/config_mgmt/tools/subdomain_takeover_checker.py` (full rewrite)

Pattern: matches `FfufTool` — `execute()` override, `build_command`/`parse_output` raise `NotImplementedError`, all detection logic in pure module-level functions.

**Module-level constants:**
```python
_SECTION_ID = "WSTG-CONF-10"
_COMMON_SUBDOMAINS: list[str]   # ~200 common prefixes
```

**Pure functions (all unit-testable without I/O):**

| Function | Input | Output |
|---|---|---|
| `_build_subdomain_list(db_assets, target_domain)` | list of raw asset strings + bare domain | deduplicated list of hostnames |
| `_parse_subjack_output(text)` | subjack JSON stdout | `list[dict]` with keys `subdomain`, `service`, `vulnerable` |
| `_classify_subjack_result(entry)` | one parsed subjack entry | `{"vulnerability": {..., "section_id": "WSTG-CONF-10"}}` |
| `_parse_nuclei_output(text)` | nuclei NDJSON stdout | `list[dict]` with keys `template_id`, `host`, `matched_at`, `severity`, `name` |
| `_classify_nuclei_result(entry)` | one parsed nuclei entry | `{"vulnerability": {..., "section_id": "WSTG-CONF-10"}}` |

**`SubdomainTakeoverChecker.execute()` flow:**
```
1.  cooldown check → early return if within COOLDOWN_HOURS
2.  acquire LIGHT semaphore
3.  emit TOOL_PROGRESS 0%
4.  scope check → early return if target out of scope
5.  query DB assets for target_id
6.  _build_subdomain_list() → write to NamedTemporaryFile A
7.  if empty → return {found:0, ...}
8.  emit TOOL_PROGRESS 20%
9.  run_subprocess: subjack -w <A> -o <B.json> -t 20 -ssl -a
10. _parse_subjack_output(B) → _classify_subjack_result() for each → collect findings + suspects
11. write suspects to NamedTemporaryFile C
12. emit TOOL_PROGRESS 60%
13. if suspects not empty:
        run_subprocess: nuclei -l <C> -t /nuclei-templates/custom/
                               -t /nuclei-templates/community/http/takeovers/
                               -json -o <D.json>
        _parse_nuclei_output(D) → _classify_nuclei_result() for each → append to findings
14. deduplicate findings by (subdomain + service/template_id)
15. for each finding: _process_result() → scope check + Vulnerability DB insert
16. update job_state.last_tool_executed + last_seen
17. emit TOOL_PROGRESS 100%
18. return {found, in_scope, new, skipped_cooldown: False}
```

All temp files cleaned up in `finally` blocks. `FileNotFoundError` on either binary → log warning, skip that phase, continue to next. `asyncio.TimeoutError` per subprocess → log, skip that phase.

### Severity mapping

| Source | Condition | Severity |
|---|---|---|
| subjack | `vulnerable: true` | `critical` |
| subjack | `vulnerable: false` (dangling CNAME) | `high` |
| nuclei | severity `critical` or `high` | `critical` |
| nuclei | severity `medium` | `high` |
| nuclei | severity `low` or `info` | `medium` |

All vulnerabilities written with `section_id = "WSTG-CONF-10"` and `worker_type = "config_mgmt"`.

---

## Dockerfile Changes (`docker/Dockerfile.config_mgmt`)

**Go builder stage** — add two installs alongside ffuf:
```dockerfile
RUN go install github.com/haccer/subjack@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Runtime stage** — copy binaries and templates:
```dockerfile
COPY --from=go-builder /go/bin/subjack  /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei   /usr/local/bin/

# Curated takeover templates (checked into repo at workers/config_mgmt/nuclei-templates/)
COPY workers/config_mgmt/nuclei-templates/ /nuclei-templates/custom/

# Community templates fetched at build time
RUN nuclei -update-templates -ud /nuclei-templates/community || true
```

The `|| true` guard prevents build failure when the network is unavailable; the tool falls back to custom templates only.

---

## Template Delivery

The curated templates from `Custom-Nuclei-Templates/takeovers/` are copied into `workers/config_mgmt/nuclei-templates/` as part of this implementation. They become a first-class project asset, checked into the repo. Updates are applied by replacing files in that directory.

---

## New Files

| Path | Purpose |
|---|---|
| `workers/config_mgmt/tools/subdomain_takeover_checker.py` | Full rewrite |
| `workers/config_mgmt/nuclei-templates/` | Curated takeover templates (copied from host) |
| `tests/unit/config_mgmt/test_subdomain_takeover_checker.py` | Pure-function unit tests |

## Modified Files

| Path | Change |
|---|---|
| `docker/Dockerfile.config_mgmt` | Add subjack + nuclei binaries; copy templates; fetch community templates |

---

## Unit Tests (`tests/unit/config_mgmt/test_subdomain_takeover_checker.py`)

All tests are synchronous, no mocking, no DB, no subprocess:

**`_build_subdomain_list`**
- Deduplicates overlapping DB + wordlist entries
- Strips schemes and paths from DB asset values
- Filters hostnames not under the target domain
- Always includes wordlist-generated entries
- Handles empty DB input

**`_parse_subjack_output`**
- Returns `[]` for empty or malformed JSON
- Parses vulnerable entries correctly
- Parses non-vulnerable (dangling) entries correctly

**`_classify_subjack_result`**
- `vulnerable=True` → `severity: "critical"`
- `vulnerable=False` → `severity: "high"`
- Always sets `section_id: "WSTG-CONF-10"`
- `location` field equals the subdomain value
- `name` field includes the service name

**`_parse_nuclei_output`**
- Returns `[]` for empty output
- Parses single NDJSON line
- Parses multiple NDJSON lines
- Skips malformed lines, keeps valid ones

**`_classify_nuclei_result`**
- nuclei `critical`/`high` → `"critical"`
- nuclei `medium` → `"high"`
- Always sets `section_id: "WSTG-CONF-10"`
- `location` field equals `matched_at`

**`_SECTION_ID` constant**
- Equals `"WSTG-CONF-10"`

---

## Error Handling Summary

| Failure mode | Behaviour |
|---|---|
| subjack binary missing | Log warning, skip Phase 2, proceed to Phase 3 |
| nuclei binary missing | Log warning, skip Phase 3 |
| subjack timeout | Log warning, skip Phase 2 |
| nuclei timeout | Log warning, skip Phase 3 |
| No subdomains assembled | Return `{found:0, in_scope:0, new:0}` immediately |
| Empty subjack suspects | Skip Phase 3 entirely |
| Temp file cleanup | Always in `finally` block |

---

## What Does Not Change

- `pipeline.py` — no change
- `playbooks.py` — no change  
- `worker-stages.ts` — no change
- `concurrency.py` — no change
- `tools/__init__.py` — no change
- `base_tool.py` — no change
