# Phase 10 — Cloud Testing Worker Design Document

**Date:** 2026-03-19
**Scope:** Phase 10 — Cloud-Testing-Engine Dockerized worker (unauthenticated cloud resource assessment)

## Overview

The Cloud Testing Worker (`cloud_worker`) performs unauthenticated cloud resource discovery and security assessment across AWS, Azure, and GCP. It runs as a single Docker container, focused on identifying publicly exposed buckets/blobs, misconfigured permissions, sensitive file exposure, and leaked credentials.

### Key Decisions

- **Queue:** `cloud_queue` / `cloud_group`
- **Container name:** `cloud-worker-{hostname}`
- **Toolchain:** CloudEnum (OSINT discovery) + custom BucketProber (permissions, file listing, config checks via boto3/azure-storage/google-cloud-storage) + TruffleHog (secret scanning on readable buckets)
- **No Prowler/SkyArk** — unauthenticated checks built into BucketProber; authenticated IAM tools out of scope for bug bounty
- **Input:** Dual-source — scan `assets` table for cloud URL patterns + existing `cloud_assets` rows + CloudEnum fresh discovery
- **Pipeline:** 4 stages — Discovery → Probing → Deep Scan → Feed-back
- **DB table:** Uses existing `CloudAsset` model (no new tables)
- **Concurrency:** Heavy (CloudEnum, TruffleHog) / Light (BucketProber, file listing)
- **Feed-back:** Domains/IPs to `recon_queue`, credential findings generate `cloud_credential_leak` alert via SSE
- **No cloud CLIs needed** — SDK calls via Python libraries (boto3, azure-storage-blob, google-cloud-storage), not aws-cli/azure-cli/gcloud

## Directory Layout

```
workers/cloud_worker/
    __init__.py
    base_tool.py              # CloudTestTool(ABC)
    concurrency.py            # WeightClass/semaphore pattern
    pipeline.py               # 4-stage Pipeline class
    main.py                   # Queue listener entry point
    tools/
        __init__.py
        # Stage 1 — Discovery
        cloud_enum.py             # CloudEnum wrapper for multi-cloud OSINT
        asset_scraper.py          # Query assets + cloud_assets tables for cloud URLs
        # Stage 2 — Probing
        bucket_prober.py          # Unified AWS/Azure/GCP permission + config checks
        # Stage 3 — Deep Scan
        file_lister.py            # List objects in readable buckets, flag sensitive filenames
        trufflehog_cloud.py       # TruffleHog native bucket/blob scanning
        # Stage 4 — Feed-back
        cloud_feedbacker.py       # Push discovered endpoints to recon_queue + credential alerts
```

## Base Tool — `CloudTestTool(ABC)`

Mirrors `ApiTestTool` with cloud-specific helpers:

- `_get_cloud_assets(target_id)` — fetch all `CloudAsset` rows for a target
- `_get_cloud_urls_from_assets(target_id)` — query `assets` table for URLs matching `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.storage.googleapis.com`, `*.appspot.com`, `*.firebaseio.com`
- `_save_cloud_asset(target_id, provider, asset_type, url, is_public, findings)` — upsert `CloudAsset` row
- `_save_vulnerability(...)` — insert Vulnerability + Alert for critical/high (same pattern as ApiTestTool)
- `_save_asset(...)` — scope-check and upsert Asset
- `_create_alert(...)` — write alert to DB + push to Redis SSE
- `run_subprocess(cmd, timeout)` — async subprocess runner
- `check_cooldown()` / `update_tool_state()` — standard cooldown pattern

## 4-Stage Pipeline

### Stage 1 — Discovery

**`cloud_enum.py`** — CloudEnum wrapper:
- Run `cloud_enum -k <target_domain>` with optional `-k` mutations from target profile keywords
- Parse stdout for discovered S3 buckets, Azure containers, GCP buckets
- Upsert each into `cloud_assets` with `provider` detected from URL pattern
- Weight: HEAVY (network-intensive, rate-limited by providers)

**`asset_scraper.py`** — Dual-source table scan:
- Query `assets` table WHERE `asset_value` ILIKE any of: `%s3.amazonaws.com%`, `%blob.core.windows.net%`, `%storage.googleapis.com%`, `%appspot.com%`, `%firebaseio.com%`
- Query existing `cloud_assets` rows for the target
- Deduplicate by URL, upsert any missing into `cloud_assets`
- Detect provider from URL pattern: `s3.amazonaws.com` → `aws`, `blob.core.windows.net` → `azure`, `storage.googleapis.com`/`appspot.com`/`firebaseio.com` → `gcp`
- Weight: LIGHT (DB queries only)

### Stage 2 — Probing

**`bucket_prober.py`** — Unified prober with internal provider dispatch:
- Iterate all `cloud_assets` for the target
- Dispatch based on `provider` field:
  - **AWS S3:** Anonymous `boto3` client — `head_bucket()`, `get_bucket_acl()`, `get_bucket_policy()`, `list_objects_v2()` (1 page). Check versioning status, logging status.
  - **Azure Blob:** Anonymous `azure-storage-blob` — `get_container_properties()`, `list_blobs()` (1 page). Check public access level (blob/container/none).
  - **GCP Storage:** Anonymous `google-cloud-storage` — `get_bucket()`, `list_blobs()` (1 page). Check IAM policy for `allUsers`/`allAuthenticatedUsers`.
- Update `cloud_assets.is_public` and `cloud_assets.findings` JSONB with permission details
- Create vulnerability for any publicly writable resource (critical) or publicly readable (high)
- Scope-check each URL via `ScopeManager` before probing — skip out-of-scope resources
- Weight: HEAVY (network calls to cloud providers, respect rate limits)

### Stage 3 — Deep Scan

**`file_lister.py`** — Sensitive filename detection on readable buckets:
- Query `cloud_assets` WHERE `is_public = True` for the target
- For each readable resource, list up to 100 objects (using same SDK clients as bucket_prober)
- Match filenames against sensitive patterns: `.env`, `.sql`, `.pem`, `.key`, `.ssh`, `.git`, `.bak`, `backup`, `credentials`, `password`, `dump`, `.csv`, `.xlsx`, `config`, `.htpasswd`, `.pgpass`
- Each match creates a vulnerability (severity based on type: `.pem`/`.key`/`.ssh` = critical, `.env`/`credentials`/`.sql` = high, others = medium)
- Store matched filenames in `cloud_assets.findings` under a `"sensitive_files"` key
- Weight: LIGHT (only hits already-confirmed readable buckets)

**`trufflehog_cloud.py`** — TruffleHog native cloud scanning:
- Query `cloud_assets` WHERE `is_public = True` for the target
- For each readable resource, run TruffleHog with provider-specific source:
  - AWS: `trufflehog s3 --bucket=<name> --max-depth=100`
  - GCP: `trufflehog gcs --project-id=<id> --bucket=<name>` (best-effort, may need public project)
  - Azure: Fall back to `trufflehog filesystem` on temp-downloaded samples if native not supported
- Parse TruffleHog JSON output for verified/unverified secrets
- Each verified secret → critical vulnerability, unverified → high
- Weight: HEAVY (downloads and scans bucket content)

### Stage 4 — Feed-back

**`cloud_feedbacker.py`** — Endpoint extraction and alerting:
- Collect all domains/IPs discovered across Stages 1-3 (from cloud asset URLs, bucket contents metadata)
- Scope-check each via `ScopeManager`, upsert in-scope ones into `assets` table
- Push new in-scope assets to `recon_queue` for Recon-Core follow-up
- Query `vulnerabilities` for this target where `source_tool` is `trufflehog_cloud` — if any contain cloud credentials (AWS keys, Azure tokens, GCP service account keys), generate a `cloud_credential_leak` alert pushed to `events:{target_id}` SSE stream
- Weight: LIGHT (DB queries + Redis pushes)

## Docker Setup

### `Dockerfile.cloud`

```
FROM webbh-base AS builder
  - apt: git, golang
  - go install: cloud_enum (Go version) or pip install cloud_enum
  - pip install: trufflehog (via pip or binary download)

FROM webbh-base AS runtime
  - Debian-slim + Python 3.11
  - pip install: boto3, azure-storage-blob, google-cloud-storage, sqlalchemy[asyncpg], lib_webbh
  - Copy cloud_enum + trufflehog binaries from builder
  - ENTRYPOINT: python -m workers.cloud_worker.main
```

No sidecars needed — all tools run in-process or as subprocesses within the single container.

### docker-compose addition

```yaml
cloud-worker:
  build:
    context: .
    dockerfile: docker/Dockerfile.cloud
  env_file: shared/config/.env
  depends_on: [postgres, redis]
```

## Resource Control

- **Rate limiting:** Exponential backoff on 429/throttle responses from cloud providers. Max 3 retries per resource.
- **Scope enforcement:** Every URL checked via `ScopeManager` before probing — prevents testing buckets belonging to other organizations sharing the same cloud namespace.
- **Concurrency:** HEAVY semaphore (default 2) for CloudEnum and TruffleHog. LIGHT semaphore (default cpu_count) for DB scrapers and file listers.
- **Timeouts:** CloudEnum 300s, TruffleHog 600s per bucket, bucket-prober 30s per resource.
- **No credential storage:** Worker never stores or logs the actual secret values found by TruffleHog — only the secret type, location, and verification status go into the vulnerability description.
