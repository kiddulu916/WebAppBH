# Find Engagement Feature — Design Spec
**Date:** 2026-05-28
**Status:** Approved

---

## Overview

"Find Engagement" lets a hunter type a company name and bug bounty platform into a modal drawer on the `/campaign/new` page. The system finds the program, scrapes or calls the platform API for its full policy, and autofills every campaign creation field — scope, seed targets, rate limit, custom headers, and playbook stage rules (including out-of-scope and chain-exception flags). The hunter reviews and edits all prefilled values before confirming, at which point the modal closes and the campaign form is populated.

---

## Supported Platforms

| Platform | Discovery | Policy Fetch |
|---|---|---|
| HackerOne | `GET /v1/hackers/programs?query={company_name}` (authenticated) | `GET /v1/programs/{handle}` (authenticated JSON) |
| Bugcrowd | `GET https://bugcrowd.com/programs?q={company_name}` (httpx + BS4) | `GET https://bugcrowd.com/{handle}` (httpx + BS4, `data-react-props` JSON blob) |
| Intigriti | `GET https://app.intigriti.com/programs?search={company_name}` (httpx + BS4) | `GET https://app.intigriti.com/programs/{company}/{handle}/scope` (httpx + BS4, JSON-LD block) |
| YesWeHack | `GET https://yeswehack.com/programs?text={company_name}` (httpx + BS4) | `GET https://yeswehack.com/programs/{handle}` (httpx + BS4, `__NUXT_DATA__` script block) |

HackerOne requires `HACKERONE_API_TOKEN` and `HACKERONE_API_USERNAME` env vars. All other platforms are scraped unauthenticated.

---

## Data Model Changes

### `StageConfig` (`shared/lib_webbh/playbooks.py`)

Two new fields added to the existing dataclass:

```python
@dataclass
class StageConfig:
    name: str
    enabled: bool = True
    tool_timeout: int = 600
    out_of_scope: bool = False       # platform marks this attack type OOS
    chain_exception: bool = False    # OOS lifted if finding contributes to hard-impact chain
```

**Execution logic:**
- `out_of_scope=True, chain_exception=False` → stage is disabled and skipped entirely
- `out_of_scope=True, chain_exception=True` → stage runs; findings are tagged `chain_only=True`; suppressed in standalone reports unless promoted by `chain_worker`

### `Campaign` model (`shared/lib_webbh/database.py`)

New column:
```python
conditional_stages: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
```

Stores the raw engagement rules as fetched, keyed by stage name:
```json
{
  "csrf": {"out_of_scope": true, "chain_exception": true, "reason": "no CSRF unless proves critical impact"},
  "rate_limiting": {"out_of_scope": true, "chain_exception": false, "reason": "no automated rate limit testing"}
}
```

This is the source of truth. The `PlaybookConfig` `StageConfig` fields are the computed artifact derived from it at campaign creation time.

### New Dataclasses (`shared/lib_webbh/platform_api/engagement_fetcher.py`)

```python
@dataclass
class ProgramCandidate:
    name: str
    handle: str
    url: str
    platform: str

@dataclass
class StageRule:
    stage_name: str
    out_of_scope: bool
    chain_exception: bool
    reason: str

@dataclass
class EngagementResult:
    platform: str
    handle: str
    program_name: str
    in_scope: list[ScopeEntry]         # reuses existing base.py dataclass
    out_of_scope: list[ScopeEntry]
    rate_limit: int | None             # req/s if stated, else None
    custom_headers: dict[str, str]
    guidelines: str                    # raw policy text for LLM pass and review display
    stage_rules: list[StageRule]
    parse_warnings: list[str]          # non-fatal parse issues surfaced to modal

@dataclass
class CampaignFormPrefill:
    program_name: str
    seed_targets: list[str]
    in_scope: list[str]
    out_of_scope: list[str]
    rate_limit: int
    custom_headers: dict[str, str]
    guidelines: str
    conditional_stages: dict[str, dict]    # stage → {out_of_scope, chain_exception, reason}
    parse_warnings: list[str]
```

---

## Backend: `engagement_fetcher` Module

**Location:** `shared/lib_webbh/platform_api/engagement_fetcher.py`

### Entry Points

```python
async def search_programs(
    platform: str,
    company_name: str,
    credentials: dict | None = None,
) -> list[ProgramCandidate]:
    """Phase 1 — find matching programs by company name."""

async def fetch_engagement(
    platform: str,
    handle: str,
    url: str,
    credentials: dict | None = None,
    use_llm: bool = True,
) -> EngagementResult:
    """Phase 2 — fetch full policy for a known program."""
```

Both functions share a single `httpx.AsyncClient` per invocation (context manager, not per-request).

### Per-Platform Fetch Functions

Private functions inside the module:
- `_search_hackerone(client, company_name, credentials) -> list[ProgramCandidate]`
- `_search_bugcrowd(client, company_name) -> list[ProgramCandidate]`
- `_search_intigriti(client, company_name) -> list[ProgramCandidate]`
- `_search_yeswehack(client, company_name) -> list[ProgramCandidate]`
- `_fetch_hackerone(client, handle, credentials) -> dict`
- `_fetch_bugcrowd(client, url) -> dict`
- `_fetch_intigriti(client, url) -> dict`
- `_fetch_yeswehack(client, url) -> dict`

Each `_fetch_*` returns a normalised raw dict. A shared `_parse_policy(raw, platform) -> EngagementResult` normalises it into `EngagementResult` (scope entries, rate limit, custom headers, guidelines text) before the mapper runs.

### `EngagementMapper`

Pure function — no DB or network calls:

```python
class EngagementMapper:
    def map(self, result: EngagementResult) -> CampaignFormPrefill:
        ...
```

**Pass 1 — Keyword map:**

`ATTACK_KEYWORD_MAP: dict[str, list[str]]` maps every stage name in `PIPELINE_STAGES` to a list of keywords/phrases. The mapper scans the `guidelines` text for disallowed mentions. For each match, a regex checks for an exception clause within 80 characters: patterns like `unless .{0,80}(critical|deeper|higher|greater|harder|significant) impact` set `chain_exception=True` on the resulting `StageRule`.

Example entries:
```python
ATTACK_KEYWORD_MAP = {
    "csrf":                   ["csrf", "cross-site request forgery"],
    "stored_xss":             ["stored xss", "persistent xss", "stored cross-site"],
    "reflected_xss":          ["reflected xss"],
    "dom_xss":                ["dom xss", "dom-based xss"],
    "sql_injection":          ["sql injection", "sqli"],
    "ssrf":                   ["ssrf", "server-side request forgery"],
    "lockout_mechanism":      ["brute force", "credential stuffing", "account lockout"],
    "rate_limiting":          ["rate limit", "rate-limit", "automated scanning"],
    "session_fixation":       ["session fixation"],
    "clickjacking":           ["clickjacking", "click-jacking", "ui redressing"],
    "host_header_injection":  ["host header injection", "host header attack"],
    "http_smuggling":         ["http smuggling", "request smuggling"],
    # ... full coverage for all ~80 stages across all 11 workers
}
```

**Pass 2 — LLM enrichment (`use_llm=True`):**

Sends `guidelines` to `llm_client` (existing `lib_webbh` module, uses the Ollama sidecar) with a structured prompt requesting JSON output: `[{stage, out_of_scope, chain_exception, reason}]`. Merges results into the keyword map output; keyword map takes precedence on conflicts. If Ollama is unreachable or times out, this pass is skipped silently and `parse_warnings` gains `"LLM enrichment unavailable — keyword map only"`.

**Scope → form field mapping:**

- `in_scope` entries with `asset_type` in `{domain, wildcard, url, cidr}` → `in_scope` patterns
- `in_scope` entries with `asset_type in {domain, wildcard}` → also added to `seed_targets`
- All `out_of_scope` entries → `out_of_scope` patterns
- Rate limit parsed from guidelines via regex: `(\d+)\s*(req|request)s?\s*(/|\s*per\s*)\s*(s|sec|second|min|minute)` — converts to req/s, defaults to `50` if not found
- Custom headers: look for `X-` prefixed header requirements in guidelines text

---

## Backend: Orchestrator Endpoints

**New file:** `orchestrator/routes/engagements.py`
**Router prefix:** `/api/v1/engagements`

```python
POST /api/v1/engagements/search
# Body: {platform, company_name, credentials?}
# Returns: list[ProgramCandidate]
# Auto-proceeds to fetch if exactly one result — returns CampaignFormPrefill directly

POST /api/v1/engagements/fetch
# Body: {platform, handle, url, credentials?, use_llm?}
# Returns: CampaignFormPrefill
```

Registered in `orchestrator/main.py` alongside the existing campaign and resource routers.

---

## Frontend: Modal Drawer

**New component:** `dashboard/src/components/FindEngagementModal.tsx`
**Used in:** `dashboard/src/app/campaign/new/page.tsx`

A "Find Engagement" button appears at the top of the campaign creation form, above the Basic Info section. Clicking it opens the modal drawer.

### Step 1 — Search

- Platform dropdown: HackerOne / Bugcrowd / Intigriti / YesWeHack
- Company name text input
- API token input (visible only when HackerOne is selected)
- "Search" button → `POST /api/v1/engagements/search`
- Loading state while request is in flight

### Step 2 — Pick Program *(skipped if single match)*

- List of `ProgramCandidate` cards: program name + URL
- Hunter clicks one → triggers `POST /api/v1/engagements/fetch`

### Step 3 — Review & Edit

All fields from `CampaignFormPrefill` rendered as editable inputs, organised into subsections:

- **Targets**: editable list rows (add/remove), pre-filled from `seed_targets`
- **In-Scope Patterns**: editable list rows, pre-filled from `in_scope`
- **Out-of-Scope Patterns**: editable list rows, pre-filled from `out_of_scope`
- **Rate Limit**: number input (1–200), pre-filled from `rate_limit`
- **Custom Headers**: key/value pair rows (add/remove), pre-filled from `custom_headers`
- **Stage Rules**: table with columns — Stage Name, Out of Scope (toggle), Chain Exception (toggle). Pre-filled from `conditional_stages`. Hunter can flip any toggle to correct misclassifications, or add a missed stage via a dropdown populated from `PIPELINE_STAGES`
- **Guidelines**: read-only collapsible text block showing raw policy text for reference. Yellow callout above it: "Review the full policy below to catch anything the parser may have missed."
- **Re-run with LLM** button: fires `POST /api/v1/engagements/fetch` with `use_llm: true`, merges new `stage_rules` into current review state without overwriting hunter edits to other fields
- If `parse_warnings` is non-empty: amber banner listing each warning at the top of the review step

### Step 4 — Confirm

- Summary: count of seed targets, scope patterns, flagged stages
- "Apply to Campaign" button: closes modal, calls a callback that sets all relevant state in the parent `CampaignCreatorPage` component
- The new campaign form fields populate from the prefill; the hunter can make final edits before submitting

---

## Worker Changes

### `chain_worker`

At the start of the `chain_evaluation` stage, load `Campaign.conditional_stages` for the current target's campaign. Any finding whose source stage has `chain_exception: true` in `conditional_stages` is treated as a **required escalation candidate**: it must be linked to a chain whose terminal impact is `high` or `critical` severity to be promoted to reportable status. Findings that qualify are tagged `chain_only: false` (promoted). Findings that do not qualify by the time `chain_evaluation` completes remain tagged `chain_only: true` and are left for `reporting_worker` to suppress.

### `reporting_worker`

During the `deduplication` stage, any finding with `chain_only: true` and no qualifying chain association is filtered from the report dataset. These findings are:
- Not rendered in any report section
- Not counted in finding totals
- Not included in alert triggers
- Logged at `DEBUG` level: `"Suppressing chain-only finding {id} ({stage}) — no qualifying chain found"`

Both workers read `conditional_stages` from `Campaign` via `get_session()` at pipeline start. No new messaging contract or Redis stream change is needed.

---

## Error Handling

| Scenario | Behavior |
|---|---|
| No programs found for company name | Modal: "No program found for `{name}` on `{platform}` — try a different name" |
| Non-200 response from platform | Modal shows HTTP status + "Try again" button; error logged server-side |
| Scraper cannot parse scope (HTML structure changed) | `EngagementResult` returned with empty lists + warning in `parse_warnings`; modal amber banner: "Scope data could not be parsed — fill manually" |
| LLM enrichment unavailable (Ollama down/timeout) | LLM pass skipped silently; keyword map results stand; warning added to `parse_warnings` |
| H1 token missing or invalid (401) | Modal: "HackerOne API token required — enter it in the token field above" |
| Rate limit not found in policy | Defaults to `50`; shown pre-filled in review step for hunter to correct |

---

## Testing

### Unit Tests (`tests/`)

- `EngagementMapper.map()` with fixture `EngagementResult` objects:
  - Full scope, empty scope, chain-exception clause present, no rate limit stated
  - Each produces the expected `CampaignFormPrefill`
- `ATTACK_KEYWORD_MAP` coverage: each stage's keywords matched correctly against sample policy strings
- Exception regex: `"no CSRF unless proves critical impact"` → `chain_exception=True`; `"no CSRF"` → `chain_exception=False`
- `_parse_{platform}()` against static HTML fixture files in `tests/fixtures/platform_pages/`:
  - `bugcrowd_program.html`, `intigriti_program.html`, `yeswehack_program.html`
  - No live network calls; tests are fully offline

### Integration Tests

- `POST /api/v1/engagements/fetch` with mock httpx transport returning fixture HTML → correct `CampaignFormPrefill` in response
- `chain_worker` `chain_evaluation` stage: finding with `chain_only=True` promoted when linked to high-severity chain; suppressed when not
- `reporting_worker` `deduplication` stage: `chain_only=True` + no chain → finding absent from report output

### DB Migration

New Alembic migration adding:
- `conditional_stages` JSON column to `campaigns` table
- `chain_only` boolean column (default `False`) to `vulnerabilities` table — used by `chain_worker` to tag findings that require chain promotion before they can be reported

The two new `StageConfig` fields (`out_of_scope`, `chain_exception`) live in the JSON playbook blob stored in `job_state` — no separate DB column needed for those.

---

## Three-Layer Coherence

No new pipeline stages are added by this feature — only `StageConfig` gains new fields. The three-layer coherence rule (pipeline.py / playbooks.py / worker-stages.ts) is not triggered. The `conditional_stages` campaign column is a new concern that sits above the stage layer.

---

## Files Changed / Created

| File | Change |
|---|---|
| `shared/lib_webbh/platform_api/engagement_fetcher.py` | **New** — search, fetch, mapper, all platform scrapers |
| `shared/lib_webbh/platform_api/__init__.py` | Export `fetch_engagement`, `search_programs`, `CampaignFormPrefill`, `EngagementResult` |
| `shared/lib_webbh/playbooks.py` | Add `out_of_scope`, `chain_exception` to `StageConfig` |
| `shared/lib_webbh/database.py` | Add `conditional_stages` JSON column to `Campaign`; add `chain_only` bool to `Vulnerability` |
| `shared/lib_webbh/__init__.py` | Export new dataclasses |
| `orchestrator/routes/engagements.py` | **New** — `/search` and `/fetch` endpoints |
| `orchestrator/main.py` | Register engagements router |
| `dashboard/src/components/FindEngagementModal.tsx` | **New** — 4-step modal drawer |
| `dashboard/src/app/campaign/new/page.tsx` | Add "Find Engagement" button + modal integration |
| `workers/chain_worker/pipeline.py` | Read `conditional_stages`, tag `chain_only` findings |
| `workers/reporting_worker/pipeline.py` | Filter `chain_only` findings in deduplication stage |
| `shared/lib_webbh/alembic/versions/` | New migration: `conditional_stages` column |
| `tests/fixtures/platform_pages/` | **New** — static HTML fixtures for scraper tests |
| `tests/unit/test_engagement_fetcher.py` | **New** — unit tests for mapper, keyword map, parsers |
| `tests/e2e/test_engagement_endpoints.py` | **New** — integration tests for orchestrator endpoints |
