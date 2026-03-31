# M4: Info Gathering Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure the existing recon_core worker into the WSTG-aligned info_gathering worker with 10 pipeline stages covering WSTG 4.1.1–4.1.10.

**Architecture:** Follows the worker template (`2026-03-29-restructure-worker-template.md`). Migrates 16 existing tools from recon_core, creates 8 new tools. Extends Waybackurls (absorb Gauplus), extends AmassActive (absorb Knockpy).

**Tech Stack:** Python 3.10, asyncio, lib_webbh, Go recon tools (Subfinder, Amass, Httpx, Naabu, Katana, etc.), Docker multi-stage build

**Design doc:** `docs/plans/design/2026-03-29-restructure-03-info-gathering.md`

---

## Template Variables

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `info_gathering` |
| `{WORKER_DIR}` | `workers/info_gathering` |
| `{QUEUE_NAME}` | `info_gathering_queue` |
| `{BASE_TOOL_CLASS}` | `InfoGatheringTool` |
| `{EXPECTED_STAGE_COUNT}` | `10` |

## Stages (WSTG 4.1.1 → 4.1.10)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | search_engine_recon | 4.1.1 | DorkEngine (new), ArchiveProber (new) |
| 2 | web_server_fingerprint | 4.1.2 | Nmap (carry), WhatWeb (carry), Httpx (carry) |
| 3 | web_server_metafiles | 4.1.3 | MetafileParser (new) |
| 4 | enumerate_subdomains | 4.1.4 | Subfinder (carry), Assetfinder (carry), AmassPassive (carry), AmassActive (carry+extend), Massdns (carry), VHostProber (new) |
| 5 | review_comments | 4.1.5 | CommentHarvester (carry), MetadataExtractor (new) |
| 6 | identify_entry_points | 4.1.6 | FormMapper (new), Paramspider (carry), Httpx (carry) |
| 7 | map_execution_paths | 4.1.7 | Katana (carry), Hakrawler (carry) |
| 8 | fingerprint_framework | 4.1.8 | Wappalyzer (carry), CookieFingerprinter (new), Webanalyze (carry) |
| 9 | map_architecture | 4.1.9 | Naabu (carry), Waybackurls (carry+extend), ArchitectureModeler (new) |
| 10 | map_application | 4.1.10 | (combines outputs from stages 1-9 into application map — no new tools, post-processing stage) |

## Tool Weights

```python
TOOL_WEIGHTS = {
    "DorkEngine": "LIGHT",
    "ArchiveProber": "LIGHT",
    "Nmap": "HEAVY",
    "WhatWeb": "LIGHT",
    "Httpx": "LIGHT",
    "MetafileParser": "LIGHT",
    "Subfinder": "HEAVY",
    "Assetfinder": "LIGHT",
    "AmassPassive": "HEAVY",
    "AmassActive": "HEAVY",
    "Massdns": "HEAVY",
    "VHostProber": "LIGHT",
    "CommentHarvester": "LIGHT",
    "MetadataExtractor": "LIGHT",
    "FormMapper": "LIGHT",
    "Paramspider": "LIGHT",
    "Katana": "HEAVY",
    "Hakrawler": "LIGHT",
    "Wappalyzer": "LIGHT",
    "CookieFingerprinter": "LIGHT",
    "Webanalyze": "LIGHT",
    "Naabu": "HEAVY",
    "Waybackurls": "LIGHT",
    "ArchitectureModeler": "LIGHT",
}
```

## Base Tool Helpers

```python
    async def run_subprocess(self, cmd: list[str], timeout: int = 600) -> str:
        """Run an external tool binary and return stdout."""
        ...

    async def scope_check(self, target_id: int, value: str) -> bool:
        """Check if a value is in scope before processing."""
        ...

    async def save_asset(self, target_id: int, asset_type: str, asset_value: str, source_tool: str, **extra):
        """Insert an Asset record."""
        ...

    async def cooldown_check(self, tool_name: str, target_id: int) -> bool:
        """Check if this tool ran recently against this target."""
        ...
```

## Docker Binaries

```dockerfile
# Go tools installed via go install
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/hakluke/hakrawler@latest
RUN go install github.com/devanshbatham/paramspider@latest

# System packages
RUN apt-get update && apt-get install -y nmap whatweb massdns
```

## Implementation Order

Follow the worker template (tasks T1–T8), implementing tools in this order:

1. **Carry-forward tools first** (migrate from recon_core with minimal changes):
   Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns, Httpx, Nmap, WhatWeb, Katana, Hakrawler, Paramspider, Waybackurls, Naabu, Wappalyzer, Webanalyze, CommentHarvester

2. **Extended tools** (existing tools with added capabilities):
   - Waybackurls: add CommonCrawl, VirusTotal, AlienVault OTX sources (absorb Gauplus)
   - AmassActive: add zone transfer attempts, brute force (absorb Knockpy)

3. **New tools**:
   DorkEngine, ArchiveProber, MetafileParser, VHostProber, MetadataExtractor, FormMapper, CookieFingerprinter, ArchitectureModeler

For each tool, follow template task T4: write failing test → implement → pass → commit.

## Key Migration Notes

- Existing tool code lives in `workers/recon_core/tools/`. Copy and adapt — do not import from old location.
- Tool class names stay the same where possible (e.g., `SubfinderTool` → `Subfinder`). Drop the `Tool` suffix for consistency.
- All tools now subclass `InfoGatheringTool` (not `ReconTool`).
- Output format: tools write to `Asset` and `Observation` tables via `save_asset()` helper.
- Stage 10 (map_application) is a post-processing stage that reads all assets from stages 1-9 and creates a consolidated application map as an Observation record. No external tools needed.
