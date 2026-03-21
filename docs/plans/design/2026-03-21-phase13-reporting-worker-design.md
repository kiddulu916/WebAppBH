# Phase 13 — Reporting & Export Worker Design

## Overview

The Reporting Worker is a data aggregation and rendering worker. Unlike other workers that execute external tool binaries via subprocess, this worker reads findings from PostgreSQL and produces professional security report documents. It is triggered on-demand by the user, not auto-triggered by the event engine.

## Trigger Flow

1. User sends `POST /api/v1/targets/{id}/reports` with selected formats and target platform
2. Orchestrator validates the request, pushes a message to `report_queue` Redis stream
3. Reporting worker picks up the message via consumer group, runs its 4-stage pipeline
4. Generated files saved to `/app/shared/reports/{target_id}/`
5. SSE events pushed to `events:{target_id}` as each format completes
6. User lists and downloads reports via `GET /api/v1/targets/{id}/reports[/{filename}]`

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Trigger model | On-demand only | Reports are human-facing deliverables; user decides when findings are complete enough |
| PDF generation | WeasyPrint (HTML/CSS → PDF) | Natural fit with Jinja2 templates; same template works for HTML preview and PDF; lighter than Pandoc+LaTeX |
| CVSS scoring | `cvss_score` float column on Vulnerability (nullable) | Upstream workers populate when available; fallback to severity-string midpoint mapping (critical=9.5, high=7.5, medium=5.0, low=2.0, info=0.0) |
| Export formats | All three in Phase 13 | HackerOne/Bugcrowd markdown, executive summary PDF, full technical PDF. All share the same data pipeline; only the template differs |
| Platform selection | Multi-select per run | User chooses which formats to generate at trigger time; data gathering runs once regardless |
| Deduplication | Group by `(source_tool, title, severity)` | Prevents mis-grouping of generic titles while distinguishing severity variants of the same vuln class |
| PoC handling | Code blocks + screenshot embedding | `poc` field rendered as `<pre>` blocks; screenshots from `/app/shared/raw/{target_id}/` embedded as `<img>` in PDFs |
| Remediation | `remediation` text column on Vulnerability (nullable) | Upstream workers populate when available; fallback to static `remediation_map.yaml` lookup by keyword matching |
| External integrations | Deferred | Jira/Slack/Discord webhooks are out of scope for Phase 13; can be layered on later |

## Database Changes

Two new nullable columns on the `vulnerabilities` table:

```sql
ALTER TABLE vulnerabilities ADD COLUMN cvss_score FLOAT NULL;
ALTER TABLE vulnerabilities ADD COLUMN remediation TEXT NULL;
```

Added to the `Vulnerability` model in `shared/lib_webbh/database.py`. Nullable so existing rows and upstream workers are unaffected. Upstream worker updates to populate these fields are deferred until after Phase 13 is complete.

## Pipeline Stages

### Stage 1 — Data Gathering

Single async function with SQLAlchemy eager loading:

- Fetch target record with `target_profile` config
- Fetch all vulnerabilities for the target, joined with associated assets and locations
- Fetch all assets (for "Assets Discovered" summary)
- Fetch all observations (tech stack context)
- Fetch all cloud assets and findings
- Fetch all API schemas discovered
- Scan `/app/shared/raw/{target_id}/` for screenshot files, build `asset_id → [screenshot_paths]` mapping

Result: a `ReportContext` dataclass passed to subsequent stages.

### Stage 2 — Deduplication & Enrichment

- Group vulnerabilities by `(source_tool, title, severity)` into `FindingGroup` objects
- Each group holds: title, severity, description, list of `(asset, location, poc, screenshots)` tuples
- Calculate CVSS: use `cvss_score` column if present, otherwise severity-string midpoint mapping
- Attach remediation: use `remediation` column if present, otherwise `remediation_map.yaml` keyword lookup
- Sort groups by CVSS descending (critical first)
- Compute summary stats: count by severity, total unique findings, total affected assets

### Stage 3 — Rendering

- Iterate user's requested `formats` list
- Each format invokes its corresponding renderer with the enriched `ReportData`
- Markdown renderer: Jinja2 → `.md` files (platform-aware: hackerone vs bugcrowd)
- Executive PDF renderer: Jinja2 → HTML → WeasyPrint → `.pdf`
- Technical PDF renderer: Jinja2 → HTML → WeasyPrint → `.pdf`
- Push SSE event per completed format: `{"event": "report_format_complete", "format": "..."}`

### Stage 4 — Export

- Move rendered files to `/app/shared/reports/{target_id}/{target_name}_{date}_{format}.{ext}`
- Update JobState to COMPLETED
- Push final SSE event: `{"event": "report_complete", "formats": [...]}`

## Data Models

Dataclasses local to the reporting worker (not in shared lib):

- **`ReportContext`** — raw queried data: target, vulnerabilities, assets, locations, observations, cloud_assets, api_schemas, screenshot_map
- **`FindingGroup`** — deduplicated finding: title, severity, cvss_score, description, remediation, source_tool, affected_assets list
- **`AffectedAsset`** — asset_value, location (port/protocol/service), poc text, screenshot_paths
- **`ReportData`** — final enriched payload for templates: target info, finding_groups (sorted), summary_stats, metadata (generation date, platform, formats)
- **`SummaryStats`** — critical_count, high_count, medium_count, low_count, info_count, total_findings, total_affected_assets

## Template Architecture

Three template sets in `workers/reporting_worker/templates/`:

### HackerOne/Bugcrowd Markdown (`hackerone.md.j2` / `bugcrowd.md.j2`)
- Per-finding sections: Title, Severity, CVSS, Description, Steps to Reproduce (from PoC), Impact, Affected Assets, Remediation
- Platform-specific section headers and structure conventions
- One `.md` file per finding group (for copy-paste) plus `index.md` listing all findings

### Executive Summary PDF (`executive.html.j2` + `executive.css`)
- Cover page: target name, date, assessor info
- Severity distribution bar chart (CSS-rendered, no JS)
- Findings table: title, severity, CVSS, affected asset count
- No PoC detail — for stakeholders, not engineers
- Typically 1-3 pages

### Full Technical Report PDF (`technical.html.j2` + `technical.css`)
- Cover page + table of contents
- Embedded executive summary section
- Per-finding detail: title, severity, CVSS, description, affected assets with URLs/IPs/ports, PoC as `<pre>` code blocks, embedded screenshots, remediation advice
- Appendices: full asset inventory, API schemas, cloud assets
- CSS page breaks, headers/footers, print-friendly styling

### Shared Partials (`_partials/`)
- `_finding.html.j2` — single finding block reused across PDF templates
- `_header.html.j2` — report header/branding
- `_stats.html.j2` — severity bar chart and summary numbers

## API Endpoints

### `POST /api/v1/targets/{target_id}/reports`
- Body: `{"formats": ["hackerone_md", "bugcrowd_md", "executive_pdf", "technical_pdf"], "platform": "hackerone"}`
- Validates target exists and has at least one vulnerability
- Pushes to `report_queue`: `{"target_id": ..., "formats": [...], "platform": "..."}`
- Returns: `{"job_id": "<msg_id>", "status": "queued"}`

### `GET /api/v1/targets/{target_id}/reports`
- Lists generated report files for the target from `/app/shared/reports/{target_id}/`
- Returns: `[{"filename": "...", "format": "...", "size_bytes": ..., "created_at": "..."}]`

### `GET /api/v1/targets/{target_id}/reports/{filename}`
- Serves file from `/app/shared/reports/{target_id}/{filename}`
- Sets `Content-Type` (`application/pdf`, `text/markdown`) and `Content-Disposition: attachment`

## File Structure

```
workers/reporting_worker/
├── main.py                     # Entry point, listen_queue + heartbeat
├── pipeline.py                 # 4-stage pipeline with checkpointing
├── base_renderer.py            # Base class for format renderers
├── data_gatherer.py            # Stage 1: DB queries, screenshot scanning
├── deduplicator.py             # Stage 2: grouping, CVSS mapping, enrichment
├── models.py                   # ReportContext, FindingGroup, ReportData dataclasses
├── remediation_map.yaml        # Static fallback remediation advice
├── renderers/
│   ├── __init__.py
│   ├── markdown_renderer.py    # HackerOne/Bugcrowd markdown output
│   ├── executive_renderer.py   # Executive summary PDF via WeasyPrint
│   └── technical_renderer.py   # Full technical report PDF via WeasyPrint
├── templates/
│   ├── _partials/
│   │   ├── _finding.html.j2
│   │   ├── _header.html.j2
│   │   └── _stats.html.j2
│   ├── hackerone.md.j2
│   ├── bugcrowd.md.j2
│   ├── executive.html.j2
│   ├── executive.css
│   ├── technical.html.j2
│   └── technical.css
├── requirements.txt            # jinja2, weasyprint, pyyaml, python-markdown
└── Dockerfile
```

### Orchestrator additions
- `orchestrator/routes/reports.py` — new router with 3 endpoints
- Register router in `orchestrator/main.py`

### Shared lib changes
- `shared/lib_webbh/database.py` — add `cvss_score` and `remediation` columns to `Vulnerability`

### Docker
- `docker/Dockerfile.reporting` — WeasyPrint + system deps (`libpango-1.0-0`, `libcairo2`, `libgdk-pixbuf-2.0-0`)
- `docker-compose.yml` — add `reporting_worker` service

## Deferred Work

- **Upstream worker updates**: Populate `cvss_score` and `remediation` from tool output (Nuclei templates, etc.)
- **External integrations**: Jira ticket creation, Slack/Discord webhook notifications
- **Dashboard UI**: Report generation form and download page
