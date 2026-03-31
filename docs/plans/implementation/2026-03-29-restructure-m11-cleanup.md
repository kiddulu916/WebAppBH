# M11: Cleanup & Retirement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove old worker code, old Docker configurations, old Redis streams, and retired tool binaries. Update documentation to reflect the new architecture.

**Architecture:** Deletion-only phase. No new code. Removes all deprecated workers, Dockerfiles, and streaming infrastructure replaced by the WSTG-aligned restructure.

**Tech Stack:** N/A (cleanup only)

**Design doc:** `docs/plans/design/2026-03-29-restructure-12-migration.md`

**Prerequisites:** All phases M1–M10 must be complete and validated. All existing tests must pass against the new architecture before beginning cleanup.

---

## Task 1: Verify All New Workers Are Operational

**Files:** None modified — verification only.

**Step 1: Run full test suite**

```bash
pytest --tb=short
```

Expected: All tests pass. No test imports from old worker directories.

**Step 2: Verify all new workers start**

```bash
docker compose up --build -d
docker compose ps
```

Expected: All 13 worker containers + orchestrator + dashboard + postgres + redis + proxy + callback are running.

**Step 3: Verify no code references old worker names**

```bash
grep -r "recon_core\|network_worker\|fuzzing_worker\|cloud_worker\|webapp_worker\|api_worker\|vuln_scanner" \
  --include="*.py" --include="*.ts" --include="*.tsx" --include="*.yml" --include="*.yaml" \
  --exclude-dir=docs --exclude-dir=.git --exclude-dir=node_modules \
  orchestrator/ workers/ dashboard/src/ shared/ docker/ docker-compose.yml
```

Expected: No matches (only docs/ may reference old names for historical context).

**Step 4: Document results, proceed if clean. If references found, fix them first.**

---

## Task 2: Remove Old Worker Directories

**Files:**
- Delete: `workers/recon_core/` (replaced by `workers/info_gathering/`)
- Delete: `workers/network_worker/` (absorbed by `workers/config_mgmt/`)
- Delete: `workers/fuzzing_worker/` (absorbed by `workers/config_mgmt/` + `workers/input_validation/`)
- Delete: `workers/cloud_worker/` (absorbed by `workers/config_mgmt/`)
- Delete: `workers/webapp_worker/` (absorbed by `workers/input_validation/`)
- Delete: `workers/api_worker/` (absorbed by `workers/input_validation/`)
- Delete: `workers/vuln_scanner/` (absorbed by `workers/input_validation/`)

**Step 1: Remove directories**

```bash
rm -rf workers/recon_core
rm -rf workers/network_worker
rm -rf workers/fuzzing_worker
rm -rf workers/cloud_worker
rm -rf workers/webapp_worker
rm -rf workers/api_worker
rm -rf workers/vuln_scanner
```

**Step 2: Remove old test directories**

```bash
rm -rf tests/test_recon_core
rm -rf tests/test_network_worker
rm -rf tests/test_fuzzing_worker
rm -rf tests/test_cloud_worker
rm -rf tests/test_webapp_worker
rm -rf tests/test_api_worker
rm -rf tests/test_vuln_scanner
```

**Step 3: Run tests to confirm nothing breaks**

```bash
pytest --tb=short
```

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove old worker directories (replaced by WSTG-aligned workers)"
```

---

## Task 3: Remove Old Dockerfiles

**Files:**
- Delete: `docker/Dockerfile.recon_core`
- Delete: `docker/Dockerfile.network_worker`
- Delete: `docker/Dockerfile.fuzzing_worker`
- Delete: `docker/Dockerfile.cloud_worker`
- Delete: `docker/Dockerfile.webapp_worker`
- Delete: `docker/Dockerfile.api_worker`
- Delete: `docker/Dockerfile.vuln_scanner`

**Step 1: Remove old Dockerfiles**

```bash
rm -f docker/Dockerfile.recon_core
rm -f docker/Dockerfile.network_worker
rm -f docker/Dockerfile.fuzzing_worker
rm -f docker/Dockerfile.cloud_worker
rm -f docker/Dockerfile.webapp_worker
rm -f docker/Dockerfile.api_worker
rm -f docker/Dockerfile.vuln_scanner
```

**Step 2: Remove old docker-compose entries**

Edit `docker-compose.yml` — remove service definitions for:
- `worker_recon_core`
- `worker_network`
- `worker_fuzzing`
- `worker_cloud`
- `worker_webapp`
- `worker_api`
- `worker_vuln_scanner`

**Step 3: Verify docker compose is valid**

```bash
docker compose config --quiet
```

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove old Dockerfiles and docker-compose entries"
```

---

## Task 4: Remove Retired Tool Binaries & Configs

**Files:**
- Remove Nuclei references (templates, config) — WSTG structure replaces its routing role
- Remove Gauplus references (absorbed into Waybackurls)
- Remove Chaos references (absorbed into Subfinder)
- Remove Knockpy references (absorbed into AmassActive)

**Step 1: Remove Nuclei configuration**

```bash
rm -rf shared/config/nuclei-templates/
rm -f shared/config/nuclei-config.yaml
```

**Step 2: Remove any standalone tool config files for retired tools**

```bash
# Remove if they exist — these tools are now absorbed into WSTG workers
rm -f shared/config/gauplus-config.yaml
rm -f shared/config/chaos-config.yaml
rm -f shared/config/knockpy-config.yaml
```

**Step 3: Remove Nuclei, Gauplus, Chaos, Knockpy from any remaining Dockerfile.base install commands**

Edit `docker/Dockerfile.base` — remove lines like:
```dockerfile
# Remove these lines if present:
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
RUN pip install knockpy
```

**Step 4: Verify build**

```bash
docker compose build --no-cache webbh-base
```

**Step 5: Commit**

```bash
git add -A
git commit -m "chore: remove Nuclei, Gauplus, Chaos, Knockpy binaries and configs"
```

---

## Task 5: Redis Stream Cleanup Script

**Files:**
- Create: `scripts/migrate_redis_streams.py`

**Step 1: Write cleanup script**

```python
# scripts/migrate_redis_streams.py
"""
One-time script to drain and delete old Redis streams.
Run AFTER verifying no active campaigns use the old streams.

Usage: python scripts/migrate_redis_streams.py
"""
import asyncio
import os
import redis.asyncio as aioredis


OLD_STREAMS = [
    "recon_queue",
    "fuzzing_queue",
    "cloud_queue",
    "api_queue",
    "network_queue",
    "webapp_queue",
    "vuln_scanner_queue",
]


async def main():
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", "6379"))

    r = aioredis.Redis(host=redis_host, port=redis_port)

    for stream in OLD_STREAMS:
        exists = await r.exists(stream)
        if not exists:
            print(f"  {stream}: does not exist, skipping")
            continue

        pending = await r.xlen(stream)
        if pending > 0:
            print(f"  WARNING: {stream} has {pending} pending messages!")
            print(f"  These messages will be lost. Skipping.")
            print(f"  To force deletion, run: redis-cli DEL {stream}")
            continue

        await r.delete(stream)
        print(f"  {stream}: deleted")

    await r.aclose()
    print("Redis stream cleanup complete.")


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 2: Commit**

```bash
git add scripts/migrate_redis_streams.py
git commit -m "chore: add Redis stream cleanup script for old queues"
```

---

## Task 6: Update Worker Type Mappings in Job State

**Files:**
- Create: `scripts/migrate_job_state.py`

**Step 1: Write migration script**

```python
# scripts/migrate_job_state.py
"""
One-time script to remap old worker_type values in job_state table.
Run AFTER the Alembic migration from M1 has been applied.

Usage: python scripts/migrate_job_state.py
"""
import asyncio
from lib_webbh.database import get_session
from sqlalchemy import text


WORKER_MAPPING = {
    "recon_core": "info_gathering",
    "network_worker": "config_mgmt",
    "fuzzing_worker": "config_mgmt",
    "cloud_worker": "config_mgmt",
    "webapp_worker": "input_validation",
    "api_worker": "input_validation",
    "vuln_scanner": "input_validation",
}


async def main():
    async with get_session() as session:
        for old_name, new_name in WORKER_MAPPING.items():
            result = await session.execute(
                text(
                    "UPDATE job_state SET worker_type = :new WHERE worker_type = :old"
                ),
                {"new": new_name, "old": old_name},
            )
            if result.rowcount > 0:
                print(f"  Remapped {result.rowcount} rows: {old_name} -> {new_name}")
            else:
                print(f"  No rows found for: {old_name}")

        await session.commit()

    print("Job state migration complete.")


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 2: Commit**

```bash
git add scripts/migrate_job_state.py
git commit -m "chore: add job_state worker_type migration script"
```

---

## Task 7: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Update architecture section**

Update the "Worker pattern" section to list the 13 new WSTG-aligned workers instead of the old workers. Update Redis stream names. Update the worker file structure description.

Key changes:
- Replace worker list with: info_gathering, config_mgmt, identity_mgmt, authentication, authorization, session_mgmt, input_validation, error_handling, cryptography, business_logic, client_side, chain_worker, reporting
- Update queue names: `info_gathering_queue:{critical,high,normal,low}`, etc.
- Add Infrastructure Services: proxy (mitmproxy), callback (OOB listener)
- Add Campaign concept to the event flow description
- Update dependency graph (not sequential phases)
- Add `workers/proxy/` and `workers/callback/` to monorepo layout

**Step 2: Update environment variables section**

Add:
```
Resource Guard: RESOURCE_GUARD_CPU_GREEN, RESOURCE_GUARD_MEM_GREEN, etc.
Chain Worker: CHAIN_STEP_DELAY_MS (default 500)
Callback: CALLBACK_HOST, CALLBACK_PORT
Proxy: PROXY_HOST, PROXY_PORT
```

**Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for WSTG-aligned architecture"
```

---

## Task 8: Final Verification

**Step 1: Run full test suite**

```bash
pytest --tb=short -q
```

Expected: All tests pass.

**Step 2: Verify clean codebase**

```bash
# No references to old worker names outside docs/
grep -r "recon_core\|network_worker\|fuzzing_worker\|cloud_worker\|webapp_worker\|api_worker\|vuln_scanner" \
  --include="*.py" --include="*.ts" --include="*.tsx" --include="*.yml" \
  --exclude-dir=docs --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=scripts
```

Expected: No matches.

**Step 3: Verify Docker build**

```bash
docker compose build
docker compose config --quiet
```

Expected: No errors.

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "chore: final cleanup verification — all old references removed"
```
