# Find Engagement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Find Engagement" modal to `/campaign/new` that searches a bug bounty platform by company name, scrapes/fetches the full program policy, and autofills all campaign fields including playbook stage rules with out-of-scope and chain-exception flags.

**Architecture:** Two-phase lookup (search → fetch) via a new `engagement_fetcher.py` module in `platform_api/`; HackerOne uses its authenticated REST API, the other three platforms (Bugcrowd, Intigriti, YesWeHack) use `httpx` + `BeautifulSoup` scraping. An `EngagementMapper` converts the fetched policy into a `CampaignFormPrefill` via a keyword map pass and optional LLM enrichment. Two new orchestrator endpoints surface this to the frontend. A 4-step modal drawer lets the hunter review and edit every prefilled value before applying to the campaign form.

**Tech Stack:** Python 3.12, httpx, BeautifulSoup4, FastAPI, SQLAlchemy async, Alembic, React 19, Next.js 16, TypeScript, Tailwind v4, Sonner toasts.

---

## File Map

| File | Action |
|---|---|
| `shared/lib_webbh/alembic/versions/003_find_engagement.py` | New — migration: `conditional_stages` on campaigns, `chain_only` on vulnerabilities |
| `shared/lib_webbh/database.py` | Modify — add columns to `Campaign` and `Vulnerability`, add `out_of_scope`/`chain_exception` to `StageConfig` |
| `shared/lib_webbh/playbooks.py` | Modify — add `out_of_scope: bool`, `chain_exception: bool` to `StageConfig` |
| `shared/lib_webbh/platform_api/engagement_fetcher.py` | New — all dataclasses, scrapers, mapper, entry points |
| `shared/lib_webbh/platform_api/__init__.py` | Modify — export new symbols |
| `shared/lib_webbh/__init__.py` | Modify — export `CampaignFormPrefill`, `EngagementResult` |
| `orchestrator/routes/engagements.py` | New — `/search` and `/fetch` endpoints |
| `orchestrator/main.py` | Modify — register engagements router |
| `dashboard/src/lib/api.ts` | Modify — add engagement API functions and types |
| `dashboard/src/components/FindEngagementModal.tsx` | New — 4-step modal drawer |
| `dashboard/src/app/campaign/new/page.tsx` | Modify — add Find Engagement button + modal |
| `workers/chain_worker/pipeline.py` | Modify — promote chain_only findings after chain_execution |
| `workers/reporting_worker/data_gatherer.py` | Modify — filter chain_only=True vulns from report data |
| `tests/fixtures/platform_pages/bugcrowd_program.html` | New — static scraper fixture |
| `tests/fixtures/platform_pages/intigriti_program.html` | New — static scraper fixture |
| `tests/fixtures/platform_pages/yeswehack_program.html` | New — static scraper fixture |
| `tests/fixtures/platform_pages/bugcrowd_search.html` | New — static search fixture |
| `tests/fixtures/platform_pages/intigriti_search.html` | New — static search fixture |
| `tests/fixtures/platform_pages/yeswehack_search.html` | New — static search fixture |
| `tests/unit/test_engagement_fetcher.py` | New — mapper, keyword map, parser unit tests |

---

## Task 1: DB Model + Alembic Migration

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Modify: `shared/lib_webbh/playbooks.py`
- Create: `shared/lib_webbh/alembic/versions/003_find_engagement.py`

- [ ] **Step 1: Write the migration file**

```python
# shared/lib_webbh/alembic/versions/003_find_engagement.py
"""Add conditional_stages to campaigns and chain_only to vulnerabilities.

Revision ID: 003_find_engagement
Revises: 002_add_path_nodes
"""

from alembic import op
import sqlalchemy as sa

revision = "003_find_engagement"
down_revision = "002_add_path_nodes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("campaigns", sa.Column("conditional_stages", sa.JSON(), nullable=True))
    op.add_column(
        "vulnerabilities",
        sa.Column("chain_only", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index("ix_vulns_chain_only", "vulnerabilities", ["chain_only"])


def downgrade() -> None:
    op.drop_index("ix_vulns_chain_only", "vulnerabilities")
    op.drop_column("vulnerabilities", "chain_only")
    op.drop_column("campaigns", "conditional_stages")
```

- [ ] **Step 2: Add `conditional_stages` to `Campaign` model in `database.py`**

Find the `Campaign` class (around line 153). Add this column after `has_credentials`:

```python
    conditional_stages: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
```

- [ ] **Step 3: Add `chain_only` to `Vulnerability` model in `database.py`**

Find the `Vulnerability` class (around line 353). Add after `false_positive`:

```python
    chain_only: Mapped[bool] = mapped_column(Boolean, default=False)
```

Also add the index to `__table_args__`:

```python
    __table_args__ = (
        Index("ix_vulns_target_severity", "target_id", "severity"),
        Index("ix_vulns_target_created", "target_id", "created_at"),
        Index("ix_vulns_section", "section_id"),
        Index("ix_vulns_worker", "worker_type"),
        Index("ix_vulns_confirmed", "confirmed"),
        Index("ix_vulns_chain_only", "chain_only"),
    )
```

- [ ] **Step 4: Add `out_of_scope` and `chain_exception` to `StageConfig` in `playbooks.py`**

Find the `StageConfig` dataclass and replace it:

```python
@dataclass
class StageConfig:
    name: str
    enabled: bool = True
    tool_timeout: int = 600
    out_of_scope: bool = False
    chain_exception: bool = False
```

- [ ] **Step 5: Verify the orchestrator's `_add_missing_columns` will pick up the new columns**

The orchestrator uses `_add_missing_columns` on startup to sync ORM metadata to the live DB (see `orchestrator/main.py:275`). Since we added the columns to the ORM models, this will auto-apply them on next startup without needing to run Alembic explicitly in dev. No code change needed — just verify the models were added correctly by reading `database.py` and confirming both columns appear.

- [ ] **Step 6: Commit**

```bash
git add shared/lib_webbh/alembic/versions/003_find_engagement.py shared/lib_webbh/database.py shared/lib_webbh/playbooks.py
git commit -m "feat: add conditional_stages, chain_only columns and StageConfig flags"
```

---

## Task 2: Engagement Fetcher — Dataclasses + Keyword Map

**Files:**
- Create: `shared/lib_webbh/platform_api/engagement_fetcher.py`

- [ ] **Step 1: Create the module with all dataclasses and the keyword map**

```python
# shared/lib_webbh/platform_api/engagement_fetcher.py
"""Find Engagement — two-phase platform lookup and policy parser.

Phase 1 (search_programs): company name → list[ProgramCandidate]
Phase 2 (fetch_engagement): program URL/handle → EngagementResult → CampaignFormPrefill
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

from lib_webbh.platform_api.base import ScopeEntry

DEFAULT_TIMEOUT = 20.0
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

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
    in_scope: list[ScopeEntry]
    out_of_scope_entries: list[ScopeEntry]
    rate_limit: int | None
    custom_headers: dict[str, str]
    guidelines: str
    stage_rules: list[StageRule]
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class CampaignFormPrefill:
    program_name: str
    seed_targets: list[str]
    in_scope: list[str]
    out_of_scope: list[str]
    rate_limit: int
    custom_headers: dict[str, str]
    guidelines: str
    conditional_stages: dict[str, dict]
    parse_warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Attack keyword map — stage_name → keywords to match in policy text
# ---------------------------------------------------------------------------
ATTACK_KEYWORD_MAP: dict[str, list[str]] = {
    # info_gathering
    "search_engine_recon":          ["search engine", "google dork", "shodan"],
    "web_server_fingerprint":       ["fingerprint", "banner grab"],
    "web_server_metafiles":         ["robots.txt", "sitemap", "metafile"],
    "enumerate_applications":       ["enumerate application", "port scan", "application enumeration"],
    "review_comments":              ["source code review", "html comment"],
    "identify_entry_points":        ["entry point", "endpoint enumeration"],
    "aggregate_entry_points":       [],
    "map_execution_paths":          ["path mapping", "execution path"],
    "review_comments_deep":         [],
    "fingerprint_framework":        ["framework fingerprint"],
    "map_architecture":             ["architecture mapping"],
    "map_application":              ["application mapping"],
    # config_mgmt
    "network_config":               ["network configuration"],
    "network_config_cred_test":     ["default credential", "default password"],
    "platform_config":              ["platform configuration"],
    "file_extension_handling":      ["file extension"],
    "backup_files":                 ["backup file", ".bak", ".old"],
    "admin_interface_enumeration":  ["admin interface", "admin panel"],
    "api_discovery":                ["api discovery", "api enumeration"],
    "http_methods":                 ["http method", "verb tampering", "options method"],
    "hsts_testing":                 ["hsts", "strict transport"],
    "rpc_testing":                  ["rpc", "xml-rpc"],
    "file_permission":              ["file permission"],
    "file_inclusion":               ["file inclusion", "lfi", "local file inclusion", "rfi", "remote file inclusion"],
    "subdomain_takeover":           ["subdomain takeover", "dangling dns"],
    "cloud_storage":                ["s3 bucket", "cloud storage", "blob storage"],
    "csp_testing":                  ["content security policy", "csp"],
    "path_confusion":               ["path confusion", "path traversal"],
    "security_headers":             ["security header", "missing header"],
    # identity_mgmt
    "role_definitions":             ["role definition", "rbac"],
    "registration_process":         ["registration", "account creation", "sign up"],
    "account_provisioning":         ["account provisioning", "account creation"],
    "account_enumeration":          ["account enumeration", "user enumeration", "username enumeration"],
    "weak_username_policy":         ["username policy", "weak username"],
    # authentication
    "credentials_transport":        ["credential transport", "password in plaintext", "http login"],
    "default_credentials":          ["default credential", "default password", "default login"],
    "lockout_mechanism":            ["brute force", "credential stuffing", "account lockout", "brute-force"],
    "auth_bypass":                  ["authentication bypass", "auth bypass"],
    "remember_password":            ["remember password", "remember me"],
    "browser_cache":                ["browser cache", "cached credential"],
    "weak_password_policy":         ["weak password", "password policy", "password complexity"],
    "security_questions":           ["security question"],
    "password_change":              ["password change", "password reset"],
    "multi_channel_auth":           ["multi-factor", "mfa", "2fa", "otp"],
    # authorization
    "directory_traversal":          ["directory traversal", "path traversal", "../"],
    "authz_bypass":                 ["authorization bypass", "access control bypass"],
    "privilege_escalation":         ["privilege escalation", "vertical privilege"],
    "idor":                         ["idor", "insecure direct object", "bola"],
    # session_mgmt
    "session_scheme":               ["session token", "session management"],
    "cookie_attributes":            ["cookie attribute", "httponly", "secure flag", "samesite"],
    "session_fixation":             ["session fixation"],
    "exposed_variables":            ["exposed variable", "session variable"],
    "csrf":                         ["csrf", "cross-site request forgery"],
    "logout_functionality":         ["logout", "session termination"],
    "session_timeout":              ["session timeout", "session expiry"],
    "session_puzzling":             ["session puzzling", "session variable overloading"],
    "session_hijacking":            ["session hijacking", "session theft"],
    # input_validation
    "reflected_xss":                ["reflected xss", "non-persistent xss"],
    "stored_xss":                   ["stored xss", "persistent xss", "stored cross-site"],
    "http_verb_tampering":          ["verb tampering", "http verb"],
    "http_param_pollution":         ["parameter pollution", "hpp"],
    "sql_injection":                ["sql injection", "sqli"],
    "ldap_injection":               ["ldap injection"],
    "xml_injection":                ["xml injection", "xxe", "xml external entity"],
    "ssti":                         ["ssti", "server-side template injection", "template injection"],
    "xpath_injection":              ["xpath injection"],
    "imap_smtp_injection":          ["imap injection", "smtp injection", "email injection"],
    "code_injection":               ["code injection", "code execution", "rce", "remote code execution"],
    "command_injection":            ["command injection", "os injection", "shell injection"],
    "format_string":                ["format string"],
    "host_header_injection":        ["host header injection", "host header attack"],
    "ssrf":                         ["ssrf", "server-side request forgery"],
    "buffer_overflow":              ["buffer overflow"],
    "http_smuggling":               ["http smuggling", "request smuggling", "http desync"],
    "websocket_injection":          ["websocket injection", "websocket"],
    # error_handling
    "error_codes":                  ["error code", "error message", "verbose error"],
    "stack_traces":                 ["stack trace", "exception detail"],
    # cryptography
    "tls_testing":                  ["tls", "ssl", "weak cipher", "certificate"],
    "padding_oracle":               ["padding oracle", "cbc padding"],
    "plaintext_transmission":       ["plaintext", "unencrypted transmission"],
    "weak_crypto":                  ["weak cryptography", "md5", "sha1", "weak hash"],
    # business_logic
    "data_validation":              ["data validation", "input validation"],
    "request_forgery":              ["request forgery"],
    "integrity_checks":             ["integrity check", "tamper"],
    "process_timing":               ["race condition", "time-of-check", "toctou"],
    "rate_limiting":                ["rate limit", "rate-limit", "automated scanning", "automated tool"],
    "workflow_bypass":              ["workflow bypass", "business logic bypass"],
    "application_misuse":           ["application misuse", "abuse"],
    "file_upload_validation":       ["file upload", "unrestricted upload"],
    "malicious_file_upload":        ["malicious file", "malicious upload", "webshell"],
    # client_side
    "dom_xss":                      ["dom xss", "dom-based xss"],
    "clickjacking":                 ["clickjacking", "click-jacking", "ui redressing"],
    "csrf_tokens":                  ["csrf token", "anti-csrf"],
    "csp_bypass":                   ["csp bypass", "content security policy bypass"],
    "html5_injection":              ["html5 injection", "html injection"],
    "web_storage":                  ["localstorage", "sessionstorage", "web storage"],
    "client_side_logic":            ["client-side logic", "javascript logic"],
    "dom_based_injection":          ["dom injection", "dom manipulation"],
    "client_side_resource_manipulation": ["resource manipulation", "client-side resource"],
    "client_side_auth":             ["client-side authentication", "client-side auth"],
    "xss_client_side":              ["cross-site scripting"],
    "css_injection":                ["css injection"],
    "malicious_upload_client":      ["malicious upload client"],
}

# Regex to detect exception clauses like "unless proves critical impact"
_EXCEPTION_RE = re.compile(
    r"unless\s.{0,80}(critical|deeper|higher|greater|harder|significant|severe)\s*impact",
    re.IGNORECASE,
)

# Regex to parse rate limit from text: "50 requests per second", "100 req/min", etc.
_RATE_LIMIT_RE = re.compile(
    r"(\d+)\s*(?:req(?:uest)?s?)\s*(?:/|\s*per\s*)\s*(s(?:ec(?:ond)?)?|min(?:ute)?)",
    re.IGNORECASE,
)

# Regex to find custom headers required: "X-Bug-Bounty: hunter" or "include X-Foo header"
_CUSTOM_HEADER_RE = re.compile(r"(X-[A-Za-z0-9\-]+)\s*:\s*([^\n\r,]+)", re.MULTILINE)
```

- [ ] **Step 2: Commit stub**

```bash
git add shared/lib_webbh/platform_api/engagement_fetcher.py
git commit -m "feat: add engagement_fetcher dataclasses and keyword map"
```

---

## Task 3: Platform Search Functions (Phase 1)

**Files:**
- Modify: `shared/lib_webbh/platform_api/engagement_fetcher.py`
- Create: `tests/fixtures/platform_pages/bugcrowd_search.html`
- Create: `tests/fixtures/platform_pages/intigriti_search.html`
- Create: `tests/fixtures/platform_pages/yeswehack_search.html`

- [ ] **Step 1: Create search HTML fixtures**

```html
<!-- tests/fixtures/platform_pages/bugcrowd_search.html -->
<!DOCTYPE html>
<html>
<head><title>Bugcrowd Programs</title></head>
<body>
<div data-react-class="ResearcherProgramCards" data-react-props='{"programs":[{"program_id":"acme-corp","name":"Acme Corp","program_url":"/acme-corp","program_type":"bug_bounty"},{"program_id":"acme-labs","name":"Acme Labs","program_url":"/acme-labs","program_type":"vdp"}]}'></div>
</body>
</html>
```

```html
<!-- tests/fixtures/platform_pages/intigriti_search.html -->
<!DOCTYPE html>
<html>
<head><title>Intigriti Programs</title></head>
<body>
<script id="__INTIGRITI_DATA__" type="application/json">
{"programs":[{"companyHandle":"acme","programHandle":"acme-corp","name":"Acme Corp","url":"https://app.intigriti.com/programs/acme/acme-corp/scope"},{"companyHandle":"acme","programHandle":"acme-labs","name":"Acme Labs","url":"https://app.intigriti.com/programs/acme/acme-labs/scope"}]}
</script>
</body>
</html>
```

```html
<!-- tests/fixtures/platform_pages/yeswehack_search.html -->
<!DOCTYPE html>
<html>
<head><title>YesWeHack Programs</title></head>
<body>
<script id="__NUXT_DATA__" type="application/json">
{"programs":{"items":[{"slug":"acme-corp","title":"Acme Corp","url":"https://yeswehack.com/programs/acme-corp"},{"slug":"acme-labs","title":"Acme Labs","url":"https://yeswehack.com/programs/acme-labs"}]}}
</script>
</body>
</html>
```

- [ ] **Step 2: Add private search functions to `engagement_fetcher.py`**

Append to the module (after the regex definitions):

```python
# ---------------------------------------------------------------------------
# Phase 1 — Search functions
# ---------------------------------------------------------------------------

async def _search_hackerone(
    client: httpx.AsyncClient,
    company_name: str,
    credentials: dict,
) -> list[ProgramCandidate]:
    token = credentials.get("token", "")
    username = credentials.get("username", "")
    resp = await client.get(
        "https://api.hackerone.com/v1/hackers/programs",
        params={"query": company_name, "sort": "name:ascending", "page[size]": 10},
        auth=(username, token),
    )
    resp.raise_for_status()
    data = resp.json()
    candidates = []
    for prog in data.get("data", []):
        attrs = prog.get("attributes", {})
        handle = attrs.get("handle", "")
        candidates.append(ProgramCandidate(
            name=attrs.get("name", handle),
            handle=handle,
            url=f"https://hackerone.com/{handle}",
            platform="hackerone",
        ))
    return candidates


async def _search_bugcrowd(
    client: httpx.AsyncClient,
    company_name: str,
) -> list[ProgramCandidate]:
    resp = await client.get(
        "https://bugcrowd.com/programs",
        params={"q": company_name},
        headers=_BROWSER_HEADERS,
    )
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find(attrs={"data-react-class": "ResearcherProgramCards"})
    if not tag:
        return []
    try:
        props = json.loads(tag["data-react-props"])
        programs = props.get("programs", [])
    except (KeyError, json.JSONDecodeError):
        return []
    return [
        ProgramCandidate(
            name=p.get("name", p.get("program_id", "")),
            handle=p.get("program_id", ""),
            url=f"https://bugcrowd.com{p.get('program_url', '')}",
            platform="bugcrowd",
        )
        for p in programs
        if p.get("program_type") == "bug_bounty"
    ]


async def _search_intigriti(
    client: httpx.AsyncClient,
    company_name: str,
) -> list[ProgramCandidate]:
    resp = await client.get(
        "https://app.intigriti.com/programs",
        params={"search": company_name},
        headers=_BROWSER_HEADERS,
    )
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__INTIGRITI_DATA__"})
    if not tag:
        return []
    try:
        data = json.loads(tag.string or "")
        programs = data.get("programs", [])
    except json.JSONDecodeError:
        return []
    return [
        ProgramCandidate(
            name=p.get("name", ""),
            handle=p.get("programHandle", ""),
            url=p.get("url", ""),
            platform="intigriti",
        )
        for p in programs
    ]


async def _search_yeswehack(
    client: httpx.AsyncClient,
    company_name: str,
) -> list[ProgramCandidate]:
    resp = await client.get(
        "https://yeswehack.com/programs",
        params={"text": company_name},
        headers=_BROWSER_HEADERS,
    )
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__NUXT_DATA__"})
    if not tag:
        return []
    try:
        data = json.loads(tag.string or "")
        items = data.get("programs", {}).get("items", [])
    except json.JSONDecodeError:
        return []
    return [
        ProgramCandidate(
            name=p.get("title", p.get("slug", "")),
            handle=p.get("slug", ""),
            url=p.get("url", f"https://yeswehack.com/programs/{p.get('slug', '')}"),
            platform="yeswehack",
        )
        for p in items
    ]
```

- [ ] **Step 3: Write unit tests for search parsers**

```python
# tests/unit/test_engagement_fetcher.py  (create file)
"""Unit tests for engagement_fetcher — offline, no network calls."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "platform_pages"


# ---- helpers ----------------------------------------------------------------

def _html(filename: str) -> str:
    return (FIXTURE_DIR / filename).read_text(encoding="utf-8")


# ---- search parsers ---------------------------------------------------------

def test_search_bugcrowd_parses_candidates():
    from lib_webbh.platform_api.engagement_fetcher import _search_bugcrowd
    import asyncio, json
    from unittest.mock import AsyncMock, MagicMock

    html = _html("bugcrowd_search.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    candidates = asyncio.get_event_loop().run_until_complete(
        _search_bugcrowd(mock_client, "acme")
    )
    assert len(candidates) == 1  # only bug_bounty type, not vdp
    assert candidates[0].handle == "acme-corp"
    assert candidates[0].platform == "bugcrowd"
    assert "bugcrowd.com/acme-corp" in candidates[0].url


def test_search_intigriti_parses_candidates():
    from lib_webbh.platform_api.engagement_fetcher import _search_intigriti
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("intigriti_search.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    candidates = asyncio.get_event_loop().run_until_complete(
        _search_intigriti(mock_client, "acme")
    )
    assert len(candidates) == 2
    assert candidates[0].handle == "acme-corp"
    assert candidates[0].platform == "intigriti"


def test_search_yeswehack_parses_candidates():
    from lib_webbh.platform_api.engagement_fetcher import _search_yeswehack
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("yeswehack_search.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    candidates = asyncio.get_event_loop().run_until_complete(
        _search_yeswehack(mock_client, "acme")
    )
    assert len(candidates) == 2
    assert candidates[0].handle == "acme-corp"
    assert candidates[0].platform == "yeswehack"
```

- [ ] **Step 4: Run tests (expect pass)**

```bash
cd C:\Users\dat1k\Projects\WebAppBH
python -m pytest tests/unit/test_engagement_fetcher.py::test_search_bugcrowd_parses_candidates tests/unit/test_engagement_fetcher.py::test_search_intigriti_parses_candidates tests/unit/test_engagement_fetcher.py::test_search_yeswehack_parses_candidates -v
```

Expected: 3 PASSED

- [ ] **Step 5: Commit**

```bash
git add shared/lib_webbh/platform_api/engagement_fetcher.py tests/fixtures/ tests/unit/test_engagement_fetcher.py
git commit -m "feat: add platform search scrapers (bugcrowd, intigriti, yeswehack) + fixtures"
```

---

## Task 4: Platform Fetch Functions + `_parse_policy` (Phase 2)

**Files:**
- Modify: `shared/lib_webbh/platform_api/engagement_fetcher.py`
- Create: `tests/fixtures/platform_pages/bugcrowd_program.html`
- Create: `tests/fixtures/platform_pages/intigriti_program.html`
- Create: `tests/fixtures/platform_pages/yeswehack_program.html`

- [ ] **Step 1: Create program page HTML fixtures**

```html
<!-- tests/fixtures/platform_pages/bugcrowd_program.html -->
<!DOCTYPE html>
<html>
<head><title>Acme Corp - Bugcrowd</title></head>
<body>
<div data-react-class="ProgramBrief" data-react-props='{"program":{"code":"acme-corp","name":"Acme Corp","briefing_text":"No CSRF unless can prove critical impact. No automated rate limit testing. No brute force. Include X-Bug-Bounty: hunter header in all requests. Max 30 requests per second.","max_request_rate":30,"target_groups":[{"name":"Web","targets":[{"name":"*.acme.com","category":"website","in_scope":true},{"name":"api.acme.com","category":"api","in_scope":true},{"name":"status.acme.com","category":"website","in_scope":false}]}]}}'></div>
</body>
</html>
```

```html
<!-- tests/fixtures/platform_pages/intigriti_program.html -->
<!DOCTYPE html>
<html>
<head><title>Acme Corp Scope - Intigriti</title></head>
<body>
<script id="__INTIGRITI_SCOPE__" type="application/json">
{
  "program": {
    "name": "Acme Corp",
    "handle": "acme-corp",
    "policy": "No SQL injection. No SSRF unless proves deeper impact. Include X-Intigriti-Test: true header. Rate limit: 50 requests per second.",
    "domains": {
      "in_scope": [
        {"type": "url", "value": "*.acme.com", "eligible_for_bounty": true},
        {"type": "url", "value": "api.acme.com", "eligible_for_bounty": true}
      ],
      "out_of_scope": [
        {"type": "url", "value": "status.acme.com"}
      ]
    }
  }
}
</script>
</body>
</html>
```

```html
<!-- tests/fixtures/platform_pages/yeswehack_program.html -->
<!DOCTYPE html>
<html>
<head><title>Acme Corp - YesWeHack</title></head>
<body>
<script id="__NUXT_DATA__" type="application/json">
{
  "program": {
    "title": "Acme Corp",
    "slug": "acme-corp",
    "guidelines": "No clickjacking. No stored XSS unless shows harder impact. No automated scanning. Max requests: 20 requests/second.",
    "scopes": [
      {"scope_type": "web_application", "asset": "*.acme.com", "eligible_bounty": true, "out_of_scope": false},
      {"scope_type": "web_application", "asset": "old.acme.com", "eligible_bounty": false, "out_of_scope": true}
    ]
  }
}
</script>
</body>
</html>
```

- [ ] **Step 2: Add private fetch functions to `engagement_fetcher.py`**

Append to the module:

```python
# ---------------------------------------------------------------------------
# Phase 2 — Fetch functions (return normalised raw dict)
# ---------------------------------------------------------------------------

_RAW_KEYS = ("program_name", "in_scope_raw", "out_of_scope_raw", "guidelines")


async def _fetch_hackerone(
    client: httpx.AsyncClient,
    handle: str,
    credentials: dict,
) -> dict:
    token = credentials.get("token", "")
    username = credentials.get("username", "")
    resp = await client.get(
        f"https://api.hackerone.com/v1/programs/{handle}",
        auth=(username, token),
    )
    resp.raise_for_status()
    data = resp.json()
    attrs = data.get("data", {}).get("attributes", {})
    scopes_data = (
        data.get("data", {})
        .get("relationships", {})
        .get("structured_scopes", {})
        .get("data", [])
    )
    in_scope_raw, out_of_scope_raw = [], []
    for s in scopes_data:
        sa = s.get("attributes", {})
        entry = {
            "asset_type": sa.get("asset_type", "unknown").lower(),
            "asset_value": sa.get("asset_identifier", ""),
            "eligible_for_bounty": sa.get("eligible_for_bounty", False),
            "in_scope": not sa.get("out_of_scope", False),
        }
        if entry["in_scope"]:
            in_scope_raw.append(entry)
        else:
            out_of_scope_raw.append(entry)
    return {
        "program_name": attrs.get("name", handle),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": attrs.get("policy", ""),
    }


async def _fetch_bugcrowd(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url, headers=_BROWSER_HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find(attrs={"data-react-class": "ProgramBrief"})
    warnings: list[str] = []
    if not tag:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Bugcrowd: could not find program data block"]}
    try:
        props = json.loads(tag["data-react-props"])
        prog = props.get("program", {})
    except (KeyError, json.JSONDecodeError):
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Bugcrowd: failed to parse program data"]}

    in_scope_raw, out_of_scope_raw = [], []
    for group in prog.get("target_groups", []):
        for t in group.get("targets", []):
            entry = {
                "asset_type": t.get("category", "website").lower(),
                "asset_value": t.get("name", ""),
                "eligible_for_bounty": t.get("in_scope", False),
            }
            if t.get("in_scope", True):
                in_scope_raw.append(entry)
            else:
                out_of_scope_raw.append(entry)

    return {
        "program_name": prog.get("name", ""),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": prog.get("briefing_text", ""),
        "_warnings": warnings,
    }


async def _fetch_intigriti(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url, headers=_BROWSER_HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__INTIGRITI_SCOPE__"})
    if not tag:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Intigriti: could not find scope data block"]}
    try:
        data = json.loads(tag.string or "")
        prog = data.get("program", {})
    except json.JSONDecodeError:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Intigriti: failed to parse scope data"]}

    domains = prog.get("domains", {})
    in_scope_raw = [
        {"asset_type": d.get("type", "url"), "asset_value": d.get("value", ""),
         "eligible_for_bounty": d.get("eligible_for_bounty", True)}
        for d in domains.get("in_scope", [])
    ]
    out_of_scope_raw = [
        {"asset_type": d.get("type", "url"), "asset_value": d.get("value", ""),
         "eligible_for_bounty": False}
        for d in domains.get("out_of_scope", [])
    ]
    return {
        "program_name": prog.get("name", ""),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": prog.get("policy", ""),
        "_warnings": [],
    }


async def _fetch_yeswehack(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url, headers=_BROWSER_HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__NUXT_DATA__"})
    if not tag:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["YesWeHack: could not find data block"]}
    try:
        data = json.loads(tag.string or "")
        prog = data.get("program", {})
    except json.JSONDecodeError:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["YesWeHack: failed to parse program data"]}

    in_scope_raw, out_of_scope_raw = [], []
    for s in prog.get("scopes", []):
        entry = {
            "asset_type": s.get("scope_type", "web_application"),
            "asset_value": s.get("asset", ""),
            "eligible_for_bounty": s.get("eligible_bounty", False),
        }
        if s.get("out_of_scope", False):
            out_of_scope_raw.append(entry)
        else:
            in_scope_raw.append(entry)

    return {
        "program_name": prog.get("title", ""),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": prog.get("guidelines", ""),
        "_warnings": [],
    }


def _parse_policy(raw: dict, platform: str, handle: str) -> EngagementResult:
    """Convert a normalised raw dict from any _fetch_* function into EngagementResult."""
    warnings: list[str] = raw.get("_warnings", [])

    in_scope = [
        ScopeEntry(
            asset_type=e.get("asset_type", "unknown"),
            asset_value=e.get("asset_value", ""),
            eligible_for_bounty=e.get("eligible_for_bounty", True),
        )
        for e in raw.get("in_scope_raw", [])
        if e.get("asset_value")
    ]
    out_of_scope_entries = [
        ScopeEntry(
            asset_type=e.get("asset_type", "unknown"),
            asset_value=e.get("asset_value", ""),
            eligible_for_bounty=False,
        )
        for e in raw.get("out_of_scope_raw", [])
        if e.get("asset_value")
    ]

    guidelines = raw.get("guidelines", "")

    # Parse rate limit
    rate_limit: int | None = None
    m = _RATE_LIMIT_RE.search(guidelines)
    if m:
        val = int(m.group(1))
        unit = m.group(2).lower()
        rate_limit = val if unit.startswith("s") else max(1, val // 60)

    # Parse custom headers
    custom_headers: dict[str, str] = {}
    for hm in _CUSTOM_HEADER_RE.finditer(guidelines):
        custom_headers[hm.group(1).strip()] = hm.group(2).strip()

    if not in_scope and not out_of_scope_entries:
        warnings.append("Scope data could not be parsed — fill manually")

    return EngagementResult(
        platform=platform,
        handle=handle,
        program_name=raw.get("program_name", ""),
        in_scope=in_scope,
        out_of_scope_entries=out_of_scope_entries,
        rate_limit=rate_limit,
        custom_headers=custom_headers,
        guidelines=guidelines,
        stage_rules=[],
        parse_warnings=warnings,
    )
```

- [ ] **Step 3: Write tests for fetch parsers**

Add to `tests/unit/test_engagement_fetcher.py`:

```python
def test_fetch_bugcrowd_parses_scope():
    from lib_webbh.platform_api.engagement_fetcher import _fetch_bugcrowd, _parse_policy
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("bugcrowd_program.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    raw = asyncio.get_event_loop().run_until_complete(
        _fetch_bugcrowd(mock_client, "https://bugcrowd.com/acme-corp")
    )
    result = _parse_policy(raw, "bugcrowd", "acme-corp")

    assert result.program_name == "Acme Corp"
    assert len(result.in_scope) == 2
    assert len(result.out_of_scope_entries) == 1
    assert result.out_of_scope_entries[0].asset_value == "status.acme.com"
    assert result.rate_limit == 30
    assert "X-Bug-Bounty" in result.custom_headers
    assert result.custom_headers["X-Bug-Bounty"] == "hunter"


def test_fetch_intigriti_parses_scope():
    from lib_webbh.platform_api.engagement_fetcher import _fetch_intigriti, _parse_policy
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("intigriti_program.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    raw = asyncio.get_event_loop().run_until_complete(
        _fetch_intigriti(mock_client, "https://app.intigriti.com/programs/acme/acme-corp/scope")
    )
    result = _parse_policy(raw, "intigriti", "acme-corp")

    assert result.program_name == "Acme Corp"
    assert len(result.in_scope) == 2
    assert len(result.out_of_scope_entries) == 1
    assert result.rate_limit == 50


def test_fetch_yeswehack_parses_scope():
    from lib_webbh.platform_api.engagement_fetcher import _fetch_yeswehack, _parse_policy
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    html = _html("yeswehack_program.html")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = html
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    raw = asyncio.get_event_loop().run_until_complete(
        _fetch_yeswehack(mock_client, "https://yeswehack.com/programs/acme-corp")
    )
    result = _parse_policy(raw, "yeswehack", "acme-corp")

    assert result.program_name == "Acme Corp"
    assert len(result.in_scope) == 1
    assert len(result.out_of_scope_entries) == 1
    assert result.rate_limit == 20


def test_parse_policy_empty_scope_adds_warning():
    from lib_webbh.platform_api.engagement_fetcher import _parse_policy

    raw = {"program_name": "Test", "in_scope_raw": [], "out_of_scope_raw": [],
           "guidelines": "", "_warnings": []}
    result = _parse_policy(raw, "bugcrowd", "test")
    assert any("fill manually" in w for w in result.parse_warnings)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/unit/test_engagement_fetcher.py -k "fetch" -v
```

Expected: 4 PASSED

- [ ] **Step 5: Commit**

```bash
git add shared/lib_webbh/platform_api/engagement_fetcher.py tests/fixtures/platform_pages/
git commit -m "feat: add platform fetch scrapers (bugcrowd, intigriti, yeswehack) + parse_policy"
```

---

## Task 5: EngagementMapper

**Files:**
- Modify: `shared/lib_webbh/platform_api/engagement_fetcher.py`

- [ ] **Step 1: Write failing tests for EngagementMapper**

Add to `tests/unit/test_engagement_fetcher.py`:

```python
def _make_result(guidelines: str = "", in_scope=None, out_of_scope=None) -> "EngagementResult":
    from lib_webbh.platform_api.engagement_fetcher import EngagementResult
    from lib_webbh.platform_api.base import ScopeEntry
    return EngagementResult(
        platform="bugcrowd",
        handle="test",
        program_name="Test Corp",
        in_scope=in_scope or [
            ScopeEntry("domain", "*.test.com", True),
            ScopeEntry("wildcard", "api.test.com", True),
        ],
        out_of_scope_entries=out_of_scope or [
            ScopeEntry("domain", "admin.test.com", False),
        ],
        rate_limit=30,
        custom_headers={"X-Test": "true"},
        guidelines=guidelines,
        stage_rules=[],
    )


def test_mapper_basic_prefill():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper
    mapper = EngagementMapper()
    result = _make_result()
    prefill = mapper.map(result)

    assert prefill.program_name == "Test Corp"
    assert "*.test.com" in prefill.in_scope
    assert "api.test.com" in prefill.in_scope
    assert "admin.test.com" in prefill.out_of_scope
    assert "*.test.com" in prefill.seed_targets
    assert prefill.rate_limit == 30
    assert prefill.custom_headers == {"X-Test": "true"}


def test_mapper_hard_disable_stage():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper
    mapper = EngagementMapper()
    result = _make_result(guidelines="No CSRF testing allowed.")
    prefill = mapper.map(result)

    assert "csrf" in prefill.conditional_stages
    rule = prefill.conditional_stages["csrf"]
    assert rule["out_of_scope"] is True
    assert rule["chain_exception"] is False


def test_mapper_chain_exception_stage():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper
    mapper = EngagementMapper()
    result = _make_result(
        guidelines="No CSRF unless proves critical impact. No SQL injection."
    )
    prefill = mapper.map(result)

    csrf_rule = prefill.conditional_stages.get("csrf", {})
    assert csrf_rule.get("out_of_scope") is True
    assert csrf_rule.get("chain_exception") is True

    sql_rule = prefill.conditional_stages.get("sql_injection", {})
    assert sql_rule.get("out_of_scope") is True
    assert sql_rule.get("chain_exception") is False


def test_mapper_rate_limit_defaults_to_50_when_none():
    from lib_webbh.platform_api.engagement_fetcher import EngagementMapper, EngagementResult
    from lib_webbh.platform_api.base import ScopeEntry
    result = EngagementResult(
        platform="bugcrowd", handle="test", program_name="Test",
        in_scope=[ScopeEntry("domain", "x.com", True)],
        out_of_scope_entries=[], rate_limit=None,
        custom_headers={}, guidelines="", stage_rules=[],
    )
    prefill = EngagementMapper().map(result)
    assert prefill.rate_limit == 50


def test_mapper_keyword_map_coverage():
    """Every stage in PIPELINE_STAGES must appear in ATTACK_KEYWORD_MAP."""
    from lib_webbh.platform_api.engagement_fetcher import ATTACK_KEYWORD_MAP
    from lib_webbh.playbooks import PIPELINE_STAGES
    all_stages = [s for stages in PIPELINE_STAGES.values() for s in stages]
    missing = [s for s in all_stages if s not in ATTACK_KEYWORD_MAP]
    assert missing == [], f"Missing from ATTACK_KEYWORD_MAP: {missing}"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_engagement_fetcher.py -k "mapper" -v
```

Expected: ImportError or AttributeError (EngagementMapper not yet defined)

- [ ] **Step 3: Implement EngagementMapper in `engagement_fetcher.py`**

Append to the module:

```python
# ---------------------------------------------------------------------------
# EngagementMapper — pure transformation, no I/O
# ---------------------------------------------------------------------------

class EngagementMapper:
    """Convert EngagementResult → CampaignFormPrefill using keyword map + optional LLM."""

    _SEED_TYPES = {"domain", "wildcard", "url"}
    _SCOPE_TYPES = {"domain", "wildcard", "url", "cidr"}

    def map(self, result: EngagementResult) -> CampaignFormPrefill:
        seed_targets = [
            e.asset_value for e in result.in_scope
            if e.asset_type.lower() in self._SEED_TYPES and e.asset_value
        ]
        in_scope = [
            e.asset_value for e in result.in_scope
            if e.asset_type.lower() in self._SCOPE_TYPES and e.asset_value
        ]
        out_of_scope = [
            e.asset_value for e in result.out_of_scope_entries
            if e.asset_value
        ]

        conditional_stages = self._apply_keyword_map(result.guidelines)

        return CampaignFormPrefill(
            program_name=result.program_name,
            seed_targets=seed_targets,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rate_limit=result.rate_limit if result.rate_limit is not None else 50,
            custom_headers=result.custom_headers,
            guidelines=result.guidelines,
            conditional_stages=conditional_stages,
            parse_warnings=list(result.parse_warnings),
        )

    def _apply_keyword_map(self, text: str) -> dict[str, dict]:
        """Pass 1: keyword scan to find disallowed attack types."""
        lower = text.lower()
        result: dict[str, dict] = {}
        for stage, keywords in ATTACK_KEYWORD_MAP.items():
            for kw in keywords:
                idx = lower.find(kw.lower())
                if idx == -1:
                    continue
                # Check for "no/not/prohibited/disallowed" in the 40 chars before the keyword
                context_before = lower[max(0, idx - 40): idx]
                if not any(neg in context_before for neg in ("no ", "not ", "prohibit", "disallow", "forbidden", "avoid", "do not")):
                    continue
                # Check for exception clause in the 100 chars after the keyword
                context_after = text[idx: idx + 100]
                chain_exception = bool(_EXCEPTION_RE.search(context_after))
                if stage not in result:
                    result[stage] = {
                        "out_of_scope": True,
                        "chain_exception": chain_exception,
                        "reason": f"Policy mentions: '{kw}'",
                    }
                elif chain_exception and not result[stage]["chain_exception"]:
                    result[stage]["chain_exception"] = True
                break
        return result

    async def apply_llm_pass(
        self, result: EngagementResult, prefill: CampaignFormPrefill
    ) -> CampaignFormPrefill:
        """Pass 2: LLM enrichment — fills gaps the keyword map missed."""
        from lib_webbh.llm_client import LLMClient

        client = LLMClient()
        prompt = (
            "You are a bug bounty rules parser. Given the following program policy text, "
            "return a JSON array of attack types that are out of scope. "
            "For each, include: stage (from this list: "
            + ", ".join(ATTACK_KEYWORD_MAP.keys())
            + "), out_of_scope (true), chain_exception (true if the policy says the attack "
            "is allowed if it proves deeper/critical impact, else false), reason (short quote). "
            "Return ONLY valid JSON. Policy:\n\n"
            + result.guidelines
        )
        try:
            response = await client.generate(prompt, json_mode=True, temperature=0.1)
            rules = json.loads(response.text)
            if not isinstance(rules, list):
                raise ValueError("LLM returned non-list")
        except Exception:
            prefill.parse_warnings.append("LLM enrichment unavailable — keyword map only")
            return prefill

        for rule in rules:
            stage = rule.get("stage", "")
            if stage not in ATTACK_KEYWORD_MAP:
                continue
            if stage in prefill.conditional_stages:
                continue  # keyword map takes precedence
            prefill.conditional_stages[stage] = {
                "out_of_scope": bool(rule.get("out_of_scope", True)),
                "chain_exception": bool(rule.get("chain_exception", False)),
                "reason": str(rule.get("reason", "")),
            }
        return prefill
```

- [ ] **Step 4: Run mapper tests**

```bash
python -m pytest tests/unit/test_engagement_fetcher.py -k "mapper" -v
```

Expected: 5 PASSED

- [ ] **Step 5: Commit**

```bash
git add shared/lib_webbh/platform_api/engagement_fetcher.py tests/unit/test_engagement_fetcher.py
git commit -m "feat: add EngagementMapper with keyword map and LLM enrichment pass"
```

---

## Task 6: Public Entry Points + Exports

**Files:**
- Modify: `shared/lib_webbh/platform_api/engagement_fetcher.py`
- Modify: `shared/lib_webbh/platform_api/__init__.py`
- Modify: `shared/lib_webbh/__init__.py`

- [ ] **Step 1: Add public entry points to `engagement_fetcher.py`**

Append to the module:

```python
# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

async def search_programs(
    platform: str,
    company_name: str,
    credentials: dict | None = None,
) -> list[ProgramCandidate]:
    """Phase 1 — find matching programs by company name on the given platform."""
    creds = credentials or {}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        if platform == "hackerone":
            return await _search_hackerone(client, company_name, creds)
        elif platform == "bugcrowd":
            return await _search_bugcrowd(client, company_name)
        elif platform == "intigriti":
            return await _search_intigriti(client, company_name)
        elif platform == "yeswehack":
            return await _search_yeswehack(client, company_name)
        else:
            raise ValueError(f"Unsupported platform: {platform!r}")


async def fetch_engagement(
    platform: str,
    handle: str,
    url: str,
    credentials: dict | None = None,
    use_llm: bool = True,
) -> CampaignFormPrefill:
    """Phase 2 — fetch full policy for a known program and map to CampaignFormPrefill."""
    creds = credentials or {}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        if platform == "hackerone":
            raw = await _fetch_hackerone(client, handle, creds)
        elif platform == "bugcrowd":
            raw = await _fetch_bugcrowd(client, url)
        elif platform == "intigriti":
            raw = await _fetch_intigriti(client, url)
        elif platform == "yeswehack":
            raw = await _fetch_yeswehack(client, url)
        else:
            raise ValueError(f"Unsupported platform: {platform!r}")

    engagement = _parse_policy(raw, platform, handle)
    mapper = EngagementMapper()
    prefill = mapper.map(engagement)
    if use_llm:
        prefill = await mapper.apply_llm_pass(engagement, prefill)
    return prefill
```

- [ ] **Step 2: Update `shared/lib_webbh/platform_api/__init__.py`**

```python
"""Bug bounty platform API clients."""
from lib_webbh.platform_api.hackerone import HackerOneClient
from lib_webbh.platform_api.bugcrowd import BugcrowdClient
from lib_webbh.platform_api.intigriti import IntigritiClient
from lib_webbh.platform_api.yeswehack import YesWeHackClient
from lib_webbh.platform_api.engagement_fetcher import (
    search_programs,
    fetch_engagement,
    ProgramCandidate,
    EngagementResult,
    CampaignFormPrefill,
    StageRule,
)

PLATFORM_CLIENTS = {
    "hackerone": HackerOneClient,
    "bugcrowd": BugcrowdClient,
    "intigriti": IntigritiClient,
    "yeswehack": YesWeHackClient,
}

__all__ = [
    "PLATFORM_CLIENTS",
    "HackerOneClient",
    "BugcrowdClient",
    "IntigritiClient",
    "YesWeHackClient",
    "search_programs",
    "fetch_engagement",
    "ProgramCandidate",
    "EngagementResult",
    "CampaignFormPrefill",
    "StageRule",
]
```

- [ ] **Step 3: Add to `shared/lib_webbh/__init__.py`**

Find the existing import block and add after the existing platform_api imports (or add if not present):

```python
from lib_webbh.platform_api.engagement_fetcher import (
    CampaignFormPrefill,
    EngagementResult,
    ProgramCandidate,
    StageRule,
)
```

And add to `__all__`:
```python
    "CampaignFormPrefill",
    "EngagementResult",
    "ProgramCandidate",
    "StageRule",
```

- [ ] **Step 4: Verify imports work**

```bash
python -c "from lib_webbh.platform_api import search_programs, fetch_engagement, CampaignFormPrefill; print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add shared/lib_webbh/platform_api/engagement_fetcher.py shared/lib_webbh/platform_api/__init__.py shared/lib_webbh/__init__.py
git commit -m "feat: expose search_programs and fetch_engagement as public entry points"
```

---

## Task 7: Orchestrator Endpoints

**Files:**
- Create: `orchestrator/routes/engagements.py`
- Modify: `orchestrator/main.py`

- [ ] **Step 1: Create `orchestrator/routes/engagements.py`**

```python
# orchestrator/routes/engagements.py
"""Engagement lookup endpoints — search platforms and fetch program policies."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from lib_webbh import setup_logger
from lib_webbh.platform_api.engagement_fetcher import (
    CampaignFormPrefill,
    ProgramCandidate,
    fetch_engagement,
    search_programs,
)
from dataclasses import asdict

logger = setup_logger("engagements-route")
router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])

SUPPORTED_PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack"}


class EngagementSearchRequest(BaseModel):
    platform: str
    company_name: str
    credentials: dict | None = None


class EngagementFetchRequest(BaseModel):
    platform: str
    handle: str
    url: str
    credentials: dict | None = None
    use_llm: bool = True


@router.post("/search")
async def search_engagement(body: EngagementSearchRequest):
    """Phase 1: find matching programs by company name.

    Returns:
    - {"type": "prefill", "data": CampaignFormPrefill} if exactly one match
    - {"type": "candidates", "data": [ProgramCandidate]} if multiple matches
    """
    if body.platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unsupported platform: {body.platform!r}")

    try:
        candidates = await search_programs(
            platform=body.platform,
            company_name=body.company_name,
            credentials=body.credentials,
        )
    except Exception as exc:
        logger.warning("Engagement search failed", extra={"error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Platform search failed: {exc}") from exc

    if not candidates:
        raise HTTPException(
            status_code=404,
            detail=f"No program found for '{body.company_name}' on {body.platform} — try a different name",
        )

    if len(candidates) == 1:
        # Auto-proceed to fetch
        c = candidates[0]
        try:
            prefill = await fetch_engagement(
                platform=body.platform,
                handle=c.handle,
                url=c.url,
                credentials=body.credentials,
                use_llm=False,  # search auto-proceed skips LLM; hunter can re-run manually
            )
        except Exception as exc:
            logger.warning("Auto-fetch failed", extra={"error": str(exc)})
            raise HTTPException(status_code=502, detail=f"Program fetch failed: {exc}") from exc
        return {"type": "prefill", "data": asdict(prefill)}

    return {"type": "candidates", "data": [asdict(c) for c in candidates]}


@router.post("/fetch")
async def fetch_engagement_endpoint(body: EngagementFetchRequest):
    """Phase 2: fetch full policy for a known program handle/URL."""
    if body.platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unsupported platform: {body.platform!r}")

    try:
        prefill = await fetch_engagement(
            platform=body.platform,
            handle=body.handle,
            url=body.url,
            credentials=body.credentials,
            use_llm=body.use_llm,
        )
    except Exception as exc:
        logger.warning("Engagement fetch failed", extra={"error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Program fetch failed: {exc}") from exc

    return asdict(prefill)
```

- [ ] **Step 2: Register the router in `orchestrator/main.py`**

Find the existing router import block near line 385:

```python
from orchestrator.routes.resources import router as resources_router, set_guard
app.include_router(resources_router)
```

Add immediately after:

```python
from orchestrator.routes.engagements import router as engagements_router
app.include_router(engagements_router)
```

- [ ] **Step 3: Verify FastAPI routes are registered**

```bash
cd C:\Users\dat1k\Projects\WebAppBH
python -c "from orchestrator.main import app; routes = [r.path for r in app.routes]; print([r for r in routes if 'engagement' in r])"
```

Expected: `['/api/v1/engagements/search', '/api/v1/engagements/fetch']`

- [ ] **Step 4: Commit**

```bash
git add orchestrator/routes/engagements.py orchestrator/main.py
git commit -m "feat: add /api/v1/engagements/search and /fetch orchestrator endpoints"
```

---

## Task 8: Dashboard API Types + Functions

**Files:**
- Modify: `dashboard/src/lib/api.ts`

- [ ] **Step 1: Add engagement types and functions to `api.ts`**

Open `dashboard/src/lib/api.ts` and append after the existing exports:

```typescript
/* ------------------------------------------------------------------ */
/* Engagements                                                         */
/* ------------------------------------------------------------------ */

export interface ProgramCandidate {
  name: string;
  handle: string;
  url: string;
  platform: string;
}

export interface StageRule {
  out_of_scope: boolean;
  chain_exception: boolean;
  reason: string;
}

export interface CampaignFormPrefill {
  program_name: string;
  seed_targets: string[];
  in_scope: string[];
  out_of_scope: string[];
  rate_limit: number;
  custom_headers: Record<string, string>;
  guidelines: string;
  conditional_stages: Record<string, StageRule>;
  parse_warnings: string[];
}

export type EngagementSearchResponse =
  | { type: "prefill"; data: CampaignFormPrefill }
  | { type: "candidates"; data: ProgramCandidate[] };

export interface EngagementSearchPayload {
  platform: string;
  company_name: string;
  credentials?: { token?: string; username?: string };
}

export interface EngagementFetchPayload {
  platform: string;
  handle: string;
  url: string;
  credentials?: { token?: string; username?: string };
  use_llm?: boolean;
}

export async function searchEngagement(
  payload: EngagementSearchPayload
): Promise<EngagementSearchResponse> {
  return request<EngagementSearchResponse>("/api/v1/engagements/search", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchEngagement(
  payload: EngagementFetchPayload
): Promise<CampaignFormPrefill> {
  return request<CampaignFormPrefill>("/api/v1/engagements/fetch", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd C:\Users\dat1k\Projects\WebAppBH\dashboard
npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/lib/api.ts
git commit -m "feat: add engagement API types and functions to dashboard api.ts"
```

---

## Task 9: FindEngagementModal Component

**Files:**
- Create: `dashboard/src/components/FindEngagementModal.tsx`

- [ ] **Step 1: Create the modal component**

```tsx
// dashboard/src/components/FindEngagementModal.tsx
"use client";

import { useState, useRef } from "react";
import { toast } from "sonner";
import {
  searchEngagement,
  fetchEngagement,
  type ProgramCandidate,
  type CampaignFormPrefill,
  type StageRule,
} from "@/lib/api";

const PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack"] as const;
type Platform = (typeof PLATFORMS)[number];

// All stage names from PIPELINE_STAGES for the "add stage" dropdown
const ALL_STAGES = [
  "search_engine_recon","web_server_fingerprint","web_server_metafiles","enumerate_applications",
  "review_comments","identify_entry_points","aggregate_entry_points","map_execution_paths",
  "review_comments_deep","fingerprint_framework","map_architecture","map_application",
  "network_config","network_config_cred_test","platform_config","file_extension_handling",
  "backup_files","admin_interface_enumeration","api_discovery","http_methods","hsts_testing",
  "rpc_testing","file_permission","file_inclusion","subdomain_takeover","cloud_storage",
  "csp_testing","path_confusion","security_headers","role_definitions","registration_process",
  "account_provisioning","account_enumeration","weak_username_policy","credentials_transport",
  "default_credentials","lockout_mechanism","auth_bypass","remember_password","browser_cache",
  "weak_password_policy","security_questions","password_change","multi_channel_auth",
  "directory_traversal","authz_bypass","privilege_escalation","idor","session_scheme",
  "cookie_attributes","session_fixation","exposed_variables","csrf","logout_functionality",
  "session_timeout","session_puzzling","session_hijacking","reflected_xss","stored_xss",
  "http_verb_tampering","http_param_pollution","sql_injection","ldap_injection","xml_injection",
  "ssti","xpath_injection","imap_smtp_injection","code_injection","command_injection",
  "format_string","host_header_injection","ssrf","buffer_overflow","http_smuggling",
  "websocket_injection","error_codes","stack_traces","tls_testing","padding_oracle",
  "plaintext_transmission","weak_crypto","data_validation","request_forgery","integrity_checks",
  "process_timing","rate_limiting","workflow_bypass","application_misuse","file_upload_validation",
  "malicious_file_upload","dom_xss","clickjacking","csrf_tokens","csp_bypass","html5_injection",
  "web_storage","client_side_logic","dom_based_injection","client_side_resource_manipulation",
  "client_side_auth","xss_client_side","css_injection","malicious_upload_client",
];

interface Props {
  onApply: (prefill: CampaignFormPrefill) => void;
  onClose: () => void;
}

export default function FindEngagementModal({ onApply, onClose }: Props) {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [loading, setLoading] = useState(false);

  // Step 1 fields
  const [platform, setPlatform] = useState<Platform>("hackerone");
  const [companyName, setCompanyName] = useState("");
  const [apiToken, setApiToken] = useState("");

  // Step 2 candidates
  const [candidates, setCandidates] = useState<ProgramCandidate[]>([]);

  // Step 3 editable prefill state
  const [prefill, setPrefill] = useState<CampaignFormPrefill | null>(null);
  const [editSeeds, setEditSeeds] = useState<string[]>([]);
  const [editInScope, setEditInScope] = useState<string[]>([]);
  const [editOutOfScope, setEditOutOfScope] = useState<string[]>([]);
  const [editRateLimit, setEditRateLimit] = useState(50);
  const [editHeaders, setEditHeaders] = useState<{ key: string; value: string }[]>([]);
  const [editStageRules, setEditStageRules] = useState<
    Record<string, StageRule>
  >({});
  const [guidelinesOpen, setGuidelinesOpen] = useState(false);
  const [addStage, setAddStage] = useState("");
  const selectedCandidate = useRef<ProgramCandidate | null>(null);

  function loadPrefill(p: CampaignFormPrefill) {
    setPrefill(p);
    setEditSeeds(p.seed_targets);
    setEditInScope(p.in_scope);
    setEditOutOfScope(p.out_of_scope);
    setEditRateLimit(p.rate_limit);
    setEditHeaders(
      Object.entries(p.custom_headers).map(([key, value]) => ({ key, value }))
    );
    setEditStageRules({ ...p.conditional_stages });
    setStep(3);
  }

  async function handleSearch() {
    if (!companyName.trim()) { toast.error("Enter a company name"); return; }
    setLoading(true);
    try {
      const creds = platform === "hackerone" ? { token: apiToken } : undefined;
      const resp = await searchEngagement({ platform, company_name: companyName, credentials: creds });
      if (resp.type === "prefill") {
        loadPrefill(resp.data);
      } else {
        setCandidates(resp.data);
        setStep(2);
      }
    } catch {
      // toast already shown by api.ts request()
    } finally {
      setLoading(false);
    }
  }

  async function handlePickCandidate(c: ProgramCandidate) {
    selectedCandidate.current = c;
    setLoading(true);
    try {
      const creds = platform === "hackerone" ? { token: apiToken } : undefined;
      const p = await fetchEngagement({ platform, handle: c.handle, url: c.url, credentials: creds, use_llm: false });
      loadPrefill(p);
    } catch {
      // toast already shown
    } finally {
      setLoading(false);
    }
  }

  async function handleRerunLLM() {
    if (!selectedCandidate.current && prefill) {
      toast.error("Re-run only available after picking a program");
      return;
    }
    const c = selectedCandidate.current;
    if (!c) return;
    setLoading(true);
    try {
      const creds = platform === "hackerone" ? { token: apiToken } : undefined;
      const fresh = await fetchEngagement({ platform, handle: c.handle, url: c.url, credentials: creds, use_llm: true });
      // Merge new stage rules without overwriting hunter edits
      setEditStageRules((prev) => ({ ...fresh.conditional_stages, ...prev }));
      toast.success("LLM pass complete — stage rules merged");
    } catch {
      // toast already shown
    } finally {
      setLoading(false);
    }
  }

  function handleApply() {
    if (!prefill) return;
    const finalPrefill: CampaignFormPrefill = {
      ...prefill,
      seed_targets: editSeeds.filter(Boolean),
      in_scope: editInScope.filter(Boolean),
      out_of_scope: editOutOfScope.filter(Boolean),
      rate_limit: editRateLimit,
      custom_headers: Object.fromEntries(
        editHeaders.filter((h) => h.key.trim()).map((h) => [h.key.trim(), h.value.trim()])
      ),
      conditional_stages: editStageRules,
    };
    onApply(finalPrefill);
  }

  // Shared list editor
  function ListEditor({ items, onChange, placeholder }: {
    items: string[]; onChange: (v: string[]) => void; placeholder: string;
  }) {
    return (
      <div className="space-y-1">
        {items.map((item, i) => (
          <div key={i} className="flex gap-2">
            <input
              value={item}
              onChange={(e) => { const n = [...items]; n[i] = e.target.value; onChange(n); }}
              className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary input-focus"
              placeholder={placeholder}
            />
            <button type="button" onClick={() => onChange(items.filter((_, j) => j !== i))}
              className="px-2 text-sm text-danger hover:text-danger/80">×</button>
          </div>
        ))}
        <button type="button" onClick={() => onChange([...items, ""])}
          className="text-xs text-accent hover:underline">+ Add</button>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />

      {/* Drawer */}
      <div className="relative z-10 flex h-full w-full max-w-xl flex-col bg-bg-surface shadow-2xl overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <h2 className="text-lg font-semibold text-text-primary">Find Engagement</h2>
          <button onClick={onClose} className="text-text-secondary hover:text-text-primary text-xl">×</button>
        </div>

        {/* Step indicator */}
        <div className="flex gap-2 px-6 pt-4 text-xs text-text-secondary">
          {(["Search", "Pick Program", "Review & Edit", "Confirm"] as const).map((label, i) => (
            <span key={label} className={`${step === i + 1 ? "text-accent font-semibold" : ""}`}>
              {i > 0 && <span className="mr-2">›</span>}{label}
            </span>
          ))}
        </div>

        <div className="flex-1 space-y-5 px-6 py-4">

          {/* ── Step 1: Search ── */}
          {step === 1 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Platform</label>
                <select value={platform} onChange={(e) => setPlatform(e.target.value as Platform)}
                  className="w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus">
                  {PLATFORMS.map((p) => (
                    <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Company Name</label>
                <input value={companyName} onChange={(e) => setCompanyName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                  className="w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                  placeholder="e.g. Google, Shopify" />
              </div>
              {platform === "hackerone" && (
                <div>
                  <label className="block text-sm font-medium text-text-secondary mb-1">
                    HackerOne API Token <span className="text-xs text-text-secondary">(required)</span>
                  </label>
                  <input type="password" value={apiToken} onChange={(e) => setApiToken(e.target.value)}
                    autoComplete="off"
                    className="w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                    placeholder="Your H1 API token" />
                </div>
              )}
              <button onClick={handleSearch} disabled={loading}
                className="w-full rounded-md btn-launch px-4 py-2 text-sm disabled:opacity-50">
                {loading ? "Searching…" : "Search"}
              </button>
            </div>
          )}

          {/* ── Step 2: Pick Program ── */}
          {step === 2 && (
            <div className="space-y-3">
              <p className="text-sm text-text-secondary">Multiple programs found — pick the right one:</p>
              {candidates.map((c) => (
                <button key={c.handle} onClick={() => handlePickCandidate(c)} disabled={loading}
                  className="w-full rounded-lg border border-border bg-bg-surface px-4 py-3 text-left hover:border-accent/60 disabled:opacity-50 transition-colors">
                  <p className="text-sm font-semibold text-text-primary">{c.name}</p>
                  <p className="text-xs text-text-secondary mt-0.5">{c.url}</p>
                </button>
              ))}
              {loading && <p className="text-sm text-text-secondary">Fetching program policy…</p>}
            </div>
          )}

          {/* ── Step 3: Review & Edit ── */}
          {step === 3 && prefill && (
            <div className="space-y-6">
              {/* Warnings */}
              {prefill.parse_warnings.length > 0 && (
                <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-600 dark:text-amber-400">
                  <strong>Parser warnings:</strong>
                  <ul className="mt-1 list-disc list-inside space-y-0.5">
                    {prefill.parse_warnings.map((w, i) => <li key={i}>{w}</li>)}
                  </ul>
                </div>
              )}

              {/* Seed Targets */}
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Seed Targets</label>
                <ListEditor items={editSeeds} onChange={setEditSeeds} placeholder="example.com" />
              </div>

              {/* In-Scope */}
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">In-Scope Patterns</label>
                <ListEditor items={editInScope} onChange={setEditInScope} placeholder="*.example.com" />
              </div>

              {/* Out-of-Scope */}
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Out-of-Scope Patterns</label>
                <ListEditor items={editOutOfScope} onChange={setEditOutOfScope} placeholder="admin.example.com" />
              </div>

              {/* Rate Limit */}
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Rate Limit (req/s)</label>
                <input type="number" value={editRateLimit} min={1} max={200}
                  onChange={(e) => setEditRateLimit(Number(e.target.value))}
                  className="w-32 rounded-md border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary input-focus" />
              </div>

              {/* Custom Headers */}
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Custom Headers</label>
                <div className="space-y-1">
                  {editHeaders.map((h, i) => (
                    <div key={i} className="flex gap-2">
                      <input value={h.key} placeholder="X-Header-Name"
                        onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], key: e.target.value }; setEditHeaders(n); }}
                        className="w-2/5 rounded-md border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary input-focus" />
                      <input value={h.value} placeholder="value"
                        onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], value: e.target.value }; setEditHeaders(n); }}
                        className="flex-1 rounded-md border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary input-focus" />
                      <button type="button" onClick={() => setEditHeaders(editHeaders.filter((_, j) => j !== i))}
                        className="px-2 text-sm text-danger hover:text-danger/80">×</button>
                    </div>
                  ))}
                  <button type="button" onClick={() => setEditHeaders([...editHeaders, { key: "", value: "" }])}
                    className="text-xs text-accent hover:underline">+ Add header</button>
                </div>
              </div>

              {/* Stage Rules */}
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Stage Rules</label>
                {Object.keys(editStageRules).length === 0 ? (
                  <p className="text-xs text-text-secondary">No stages flagged by policy parser.</p>
                ) : (
                  <div className="rounded-lg border border-border overflow-hidden">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border bg-bg-surface">
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-secondary">Stage</th>
                          <th className="px-3 py-2 text-center text-xs font-medium text-text-secondary">Out of Scope</th>
                          <th className="px-3 py-2 text-center text-xs font-medium text-text-secondary">Chain Exception</th>
                          <th className="px-3 py-2"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(editStageRules).map(([stage, rule]) => (
                          <tr key={stage} className="border-b border-border last:border-0">
                            <td className="px-3 py-2 text-text-primary font-mono text-xs">{stage}</td>
                            <td className="px-3 py-2 text-center">
                              <input type="checkbox" checked={rule.out_of_scope}
                                onChange={(e) => setEditStageRules((prev) => ({
                                  ...prev, [stage]: { ...rule, out_of_scope: e.target.checked }
                                }))} className="rounded border-border" />
                            </td>
                            <td className="px-3 py-2 text-center">
                              <input type="checkbox" checked={rule.chain_exception}
                                disabled={!rule.out_of_scope}
                                onChange={(e) => setEditStageRules((prev) => ({
                                  ...prev, [stage]: { ...rule, chain_exception: e.target.checked }
                                }))} className="rounded border-border disabled:opacity-40" />
                            </td>
                            <td className="px-3 py-2">
                              <button type="button" onClick={() => setEditStageRules((prev) => {
                                const n = { ...prev }; delete n[stage]; return n;
                              })} className="text-xs text-danger hover:text-danger/80">Remove</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {/* Add missed stage */}
                <div className="mt-2 flex gap-2">
                  <select value={addStage} onChange={(e) => setAddStage(e.target.value)}
                    className="flex-1 rounded-md border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary input-focus">
                    <option value="">Add a stage…</option>
                    {ALL_STAGES.filter((s) => !(s in editStageRules)).map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                  <button type="button" disabled={!addStage}
                    onClick={() => {
                      if (!addStage) return;
                      setEditStageRules((prev) => ({
                        ...prev, [addStage]: { out_of_scope: true, chain_exception: false, reason: "Added manually" }
                      }));
                      setAddStage("");
                    }}
                    className="rounded-md border border-border px-3 py-1.5 text-sm text-text-primary hover:border-accent/60 disabled:opacity-40">
                    Add
                  </button>
                </div>
              </div>

              {/* Guidelines */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-sm font-medium text-text-secondary">Full Policy Guidelines</label>
                  <button type="button" onClick={() => setGuidelinesOpen(!guidelinesOpen)}
                    className="text-xs text-accent hover:underline">
                    {guidelinesOpen ? "Collapse" : "Expand"}
                  </button>
                </div>
                <p className="text-xs text-amber-600 dark:text-amber-400 mb-1">
                  Review the full policy below to catch anything the parser may have missed.
                </p>
                {guidelinesOpen && (
                  <pre className="rounded-lg border border-border bg-bg-base p-3 text-xs text-text-secondary whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {prefill.guidelines || "(No policy text found)"}
                  </pre>
                )}
              </div>

              {/* Re-run LLM */}
              <button type="button" onClick={handleRerunLLM} disabled={loading}
                className="w-full rounded-md border border-border px-4 py-2 text-sm text-text-secondary hover:border-accent/60 disabled:opacity-50">
                {loading ? "Running LLM…" : "Re-run with LLM (deeper analysis)"}
              </button>

              <button type="button" onClick={() => setStep(4)}
                className="w-full rounded-md btn-launch px-4 py-2 text-sm">
                Review & Confirm →
              </button>
            </div>
          )}

          {/* ── Step 4: Confirm ── */}
          {step === 4 && prefill && (
            <div className="space-y-4">
              <p className="text-sm text-text-secondary">About to apply the following to the campaign form:</p>
              <ul className="text-sm text-text-primary space-y-1">
                <li><span className="font-medium">Program:</span> {prefill.program_name}</li>
                <li><span className="font-medium">Seed targets:</span> {editSeeds.filter(Boolean).length}</li>
                <li><span className="font-medium">In-scope patterns:</span> {editInScope.filter(Boolean).length}</li>
                <li><span className="font-medium">Out-of-scope patterns:</span> {editOutOfScope.filter(Boolean).length}</li>
                <li><span className="font-medium">Rate limit:</span> {editRateLimit} req/s</li>
                <li><span className="font-medium">Custom headers:</span> {editHeaders.filter((h) => h.key.trim()).length}</li>
                <li><span className="font-medium">Flagged stages:</span> {Object.keys(editStageRules).length}</li>
              </ul>
              <div className="flex gap-3">
                <button type="button" onClick={() => setStep(3)}
                  className="flex-1 rounded-md border border-border px-4 py-2 text-sm text-text-secondary hover:border-accent/60">
                  ← Back
                </button>
                <button type="button" onClick={handleApply}
                  className="flex-1 rounded-md btn-launch px-4 py-2 text-sm">
                  Apply to Campaign
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Check TypeScript compiles**

```bash
cd C:\Users\dat1k\Projects\WebAppBH\dashboard
npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/FindEngagementModal.tsx
git commit -m "feat: add FindEngagementModal 4-step drawer component"
```

---

## Task 10: Wire Modal into `/campaign/new`

**Files:**
- Modify: `dashboard/src/app/campaign/new/page.tsx`

- [ ] **Step 1: Add modal state and "Find Engagement" button to `page.tsx`**

Add the import at the top of the file (after existing imports):

```typescript
import FindEngagementModal from "@/components/FindEngagementModal";
import type { CampaignFormPrefill } from "@/lib/api";
```

Add modal state after the existing `loading` state declaration:

```typescript
const [showEngagementModal, setShowEngagementModal] = useState(false);
```

Add the `handleEngagementApply` callback before `handleSubmit`:

```typescript
const handleEngagementApply = (prefill: CampaignFormPrefill) => {
  setShowEngagementModal(false);
  if (prefill.program_name) setName(prefill.program_name);
  setSeedTargets(prefill.seed_targets.map((v) => ({ id: mkId(), value: v })));
  setInScope(prefill.in_scope.map((v) => ({ id: mkId(), value: v })));
  setOutOfScope(prefill.out_of_scope.map((v) => ({ id: mkId(), value: v })));
  setRateLimit(Math.min(200, Math.max(1, prefill.rate_limit)));
  toast.success(`Engagement data applied from ${prefill.program_name || "program"}`);
};
```

Add the "Find Engagement" button at the top of the returned JSX, above the `<form>` element — insert inside the `<div className="max-w-3xl mx-auto space-y-8">` after the title block:

```tsx
{/* Find Engagement */}
<div className="flex justify-end">
  <button
    type="button"
    onClick={() => setShowEngagementModal(true)}
    className="rounded-md border border-accent/60 px-4 py-2 text-sm text-accent hover:bg-accent/10 transition-colors"
  >
    Find Engagement
  </button>
</div>

{showEngagementModal && (
  <FindEngagementModal
    onApply={handleEngagementApply}
    onClose={() => setShowEngagementModal(false)}
  />
)}
```

- [ ] **Step 2: Check TypeScript compiles**

```bash
cd C:\Users\dat1k\Projects\WebAppBH\dashboard
npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/app/campaign/new/page.tsx
git commit -m "feat: wire FindEngagementModal into campaign/new page"
```

---

## Task 11: chain_worker — Tag and Promote chain_only Findings

**Files:**
- Modify: `workers/chain_worker/pipeline.py`

- [ ] **Step 1: Add chain_only promotion logic to the pipeline**

Open `workers/chain_worker/pipeline.py`. After the existing imports, add:

```python
from lib_webbh.database import Campaign, ChainFinding, Target, Vulnerability
from sqlalchemy import select, update
```

After `STAGE_INDEX` is defined and before `class Pipeline:`, add the helper function:

```python
async def _promote_chain_only_findings(target_id: int) -> int:
    """Set chain_only=False on vulns that appear in a high/critical ChainFinding.

    Returns the count of promoted findings.
    """
    async with get_session() as session:
        # Load the campaign's conditional_stages to check if any stages are chain-exception
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()

        if not target or not target.campaign_id:
            return 0

        campaign = (await session.execute(
            select(Campaign).where(Campaign.id == target.campaign_id)
        )).scalar_one_or_none()

        conditional = (campaign.conditional_stages or {}) if campaign else {}
        chain_exception_stages = {
            stage for stage, rule in conditional.items()
            if rule.get("chain_exception")
        }
        if not chain_exception_stages:
            return 0

        # Find all high/critical chains for this target
        chains = (await session.execute(
            select(ChainFinding).where(
                ChainFinding.target_id == target_id,
                ChainFinding.severity.in_(["high", "critical"]),
            )
        )).scalars().all()

        # Collect all vulnerability IDs referenced in qualifying chains
        qualifying_vuln_ids: set[int] = set()
        for chain in chains:
            qualifying_vuln_ids.add(chain.entry_vulnerability_id)
            linked = chain.linked_vulnerability_ids or {}
            for vid in linked.get("ids", []):
                qualifying_vuln_ids.add(int(vid))

        if not qualifying_vuln_ids:
            return 0

        # Promote: clear chain_only on vulns in qualifying chains
        result = await session.execute(
            update(Vulnerability)
            .where(
                Vulnerability.id.in_(qualifying_vuln_ids),
                Vulnerability.chain_only.is_(True),
            )
            .values(chain_only=False)
        )
        await session.commit()
        return result.rowcount
```

In the `Pipeline.run()` method, add promotion after the `chain_execution` stage completes. Find where `STAGES` are iterated and stage names are checked. After the block that runs the `chain_execution` stage (when `stage.name == "chain_execution"`), add:

```python
            # After chain_execution, promote chain_only findings that made it into
            # a high/critical chain so reporting_worker surfaces them.
            if stage.name == "chain_execution":
                promoted = await _promote_chain_only_findings(target_id)
                if promoted:
                    log.info("Promoted chain_only findings", extra={"count": promoted})
```

The insertion point in `run()` is after the `asyncio.gather(*tasks)` call for the stage, still inside the `for i in range(...)` loop. Place it as:

```python
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # ... existing error checking ...

            if stage.name == "chain_execution":
                promoted = await _promote_chain_only_findings(target_id)
                if promoted:
                    log.info("Promoted chain_only findings", extra={"count": promoted})

            await self._update_phase(target_id, container_name, stage.name)
```

Read `workers/chain_worker/pipeline.py` lines 80–130 to find the exact loop structure before inserting.

- [ ] **Step 2: Commit**

```bash
git add workers/chain_worker/pipeline.py
git commit -m "feat: chain_worker promotes chain_only findings after chain_execution"
```

---

## Task 12: reporting_worker — Filter chain_only Findings

**Files:**
- Modify: `workers/reporting_worker/data_gatherer.py`

- [ ] **Step 1: Filter chain_only vulns in `gather_report_data`**

Open `workers/reporting_worker/data_gatherer.py`. In the `gather_report_data` function, find the vulnerability query (around line 22):

```python
        vulns = (await session.execute(
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset).selectinload(Asset.locations))
        )).scalars().all()
```

Replace with:

```python
        all_vulns = (await session.execute(
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset).selectinload(Asset.locations))
        )).scalars().all()

        # Suppress chain_only findings that were never promoted by chain_worker
        suppressed = [v for v in all_vulns if v.chain_only]
        vulns = [v for v in all_vulns if not v.chain_only]

        if suppressed:
            import logging
            _log = logging.getLogger("reporting_data_gatherer")
            for v in suppressed:
                _log.debug(
                    "Suppressing chain-only finding %s (%s) — no qualifying chain found",
                    v.id, v.stage_name,
                )
```

- [ ] **Step 2: Commit**

```bash
git add workers/reporting_worker/data_gatherer.py
git commit -m "feat: reporting_worker suppresses chain_only findings with no qualifying chain"
```

---

## Task 13: Run All Unit Tests

- [ ] **Step 1: Run the full unit test suite**

```bash
cd C:\Users\dat1k\Projects\WebAppBH
python -m pytest tests/unit/test_engagement_fetcher.py -v
```

Expected output (all passing):
```
tests/unit/test_engagement_fetcher.py::test_search_bugcrowd_parses_candidates PASSED
tests/unit/test_engagement_fetcher.py::test_search_intigriti_parses_candidates PASSED
tests/unit/test_engagement_fetcher.py::test_search_yeswehack_parses_candidates PASSED
tests/unit/test_engagement_fetcher.py::test_fetch_bugcrowd_parses_scope PASSED
tests/unit/test_engagement_fetcher.py::test_fetch_intigriti_parses_scope PASSED
tests/unit/test_engagement_fetcher.py::test_fetch_yeswehack_parses_scope PASSED
tests/unit/test_engagement_fetcher.py::test_parse_policy_empty_scope_adds_warning PASSED
tests/unit/test_engagement_fetcher.py::test_mapper_basic_prefill PASSED
tests/unit/test_engagement_fetcher.py::test_mapper_hard_disable_stage PASSED
tests/unit/test_engagement_fetcher.py::test_mapper_chain_exception_stage PASSED
tests/unit/test_engagement_fetcher.py::test_mapper_rate_limit_defaults_to_50_when_none PASSED
tests/unit/test_engagement_fetcher.py::test_mapper_keyword_map_coverage PASSED
```

- [ ] **Step 2: TypeScript lint**

```bash
cd C:\Users\dat1k\Projects\WebAppBH\dashboard
npm run lint
```

Expected: no errors

- [ ] **Step 3: Final commit**

```bash
cd C:\Users\dat1k\Projects\WebAppBH
git add .
git commit -m "feat: find-engagement feature complete — search, fetch, mapper, modal, worker chain_only suppression"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] Two-phase search → fetch per platform (Tasks 3–6)
- [x] H1 uses authenticated API, others use httpx + BS4 (Tasks 3–4)
- [x] `StageConfig.out_of_scope` + `chain_exception` (Task 1)
- [x] `Campaign.conditional_stages` JSON column (Task 1)
- [x] `Vulnerability.chain_only` bool column + migration (Task 1)
- [x] `EngagementResult`, `CampaignFormPrefill`, `ProgramCandidate`, `StageRule` dataclasses (Task 2)
- [x] `ATTACK_KEYWORD_MAP` full coverage of all ~80 stages (Task 2)
- [x] Exception regex detects "unless ... critical impact" pattern (Task 5)
- [x] `EngagementMapper.map()` pure function (Task 5)
- [x] Optional LLM enrichment pass (Task 5)
- [x] `search_programs` and `fetch_engagement` public entry points (Task 6)
- [x] `POST /api/v1/engagements/search` — auto-proceeds if single match (Task 7)
- [x] `POST /api/v1/engagements/fetch` (Task 7)
- [x] 4-step modal drawer with editable review step (Task 9)
- [x] Re-run LLM button merges without overwriting hunter edits (Task 9)
- [x] chain_worker promotes chain_only → False when in high/critical chain (Task 11)
- [x] reporting_worker suppresses chain_only=True findings, DEBUG logs suppression (Task 12)
- [x] Parse warnings surfaced in modal amber banner (Task 9)
- [x] Rate limit default 50 when not found (Task 5)
- [x] Unit tests for mapper, keyword map, parsers, coverage check (Tasks 3–5, 13)
- [x] Static HTML fixtures for offline testing (Tasks 3–4)
- [x] Alembic migration (Task 1)
