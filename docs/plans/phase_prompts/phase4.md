# Recon-Core

Act as an Elite Bug Bounty Automation Architect. 
Task: Create the "Recon-Core" Dockerized Worker. This is a high-concurrency, stateful reconnaissance engine designed to integrate with a Next.js/FastAPI framework.

## 1. Toolchain & Environment

- **Base Image**: Debian-slim with Go, Python 3.10+, and essential build tools.
- **Discovery Suite**: Amass, Assetfinder, Findomain, Subfinder, Sublist3r, Knockpy, Chaos (ProjectDiscovery).
- **Probing & Scanning**: Naabu, Httpx, Massdns.
- **Crawling & Fuzzing Prep**: Katana, Hakrawler, Gauplus, Waybackurls, Paramspider.
- **Config**: 
    - Load API keys (Chaos, Amass, BinaryEdge, etc.) from a `.env` file.
    - Read target parameters from `/app/shared/target_profile.json`.

## 2. State & Persistence (OAM Standard)

- **Database**: Use a shared SQLite database (`recon_assets.db`) following the **Open Asset Model (OAM)**.
- **Tables**: `assets` (Subdomains/IPs), `identities` (ASN/Org), `locations` (Ports/Services), `observations` (Tech stack, Titles), `parameters`, and `job_state`.
- **Persistence Logic**: 
    - Implement a 24-hour "cooldown." Before running heavy tools (Naabu, Katana) on an asset, check the `job_state` table. If scanned in the last 24 hours, skip to save resources.
- **State Recovery**: If the container restarts, it must query `job_state` to resume the specific tool/target phase it was executing.

## 3. The Scope Guard (Wildcards & CIDR)

Create a `ScopeManager` class that:

- Filters every found asset against a blacklist/whitelist.
- Supports wildcards (`*.target.com` matches `sub.target.com` and `a.b.target.com`).
- Supports directory wildcards (`*/admin/*`).
- Supports **CIDR range validation** (e.g., discard IPs if not in `192.168.1.0/24`).
- **Strict Rule**: Any asset failing scope check is immediately discarded and logged as "Excluded."

## 4. Orchestration Logic (`main.py`)

- **Concurrency**: Use `asyncio` with a `BoundedSemaphore` based on `os.cpu_count()`. Limit memory-heavy tools (Amass/Katana) to a strict concurrency cap to prevent OOM kills.
- **Header Injection**: Parse `custom_headers` from the target profile and inject them into all supporting tools (Httpx, Katana, etc.) using their respective CLI flags.
- **The Execution Pipeline**:
    1. **Passive Discovery**: Subfinder, Assetfinder, Chaos, Amass (Passive).
    2. **Active Discovery**: Sublist3r, Knockpy, Amass (Active).
    3. **Liveness & DNS**: Massdns -> Httpx (Filter for resolved/active only).
    4. **Port Mapping**: Naabu (only on live IPs).
    5. **Deep Recon**: Katana/Hakrawler/Waybackurls/Paramspider (only on live web services).

## 5. Frontend & Connectivity

- **Heartbeat**: Every 30 seconds, update a `heartbeat` table in the DB with `{"percent": X, "current_tool": "Y", "stats": {...}}`.
- **Alerting**: If a critical asset (e.g., `.git` directory, exposed `.env`, port 3389) is found, write a high-priority entry to an `ALERTS` table for the Next.js frontend to display.

Deliverables: Dockerfile, Python Controller, OAM SQLite Schema, and tool-specific wrapper scripts.