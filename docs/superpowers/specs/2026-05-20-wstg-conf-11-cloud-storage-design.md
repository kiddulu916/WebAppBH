# WSTG-CONF-11: Cloud Storage Auditor — Design Spec

**Date:** 2026-05-20
**WSTG reference:** WSTG-CONF-11 — Test Cloud Storage
**Worker:** `config_mgmt`
**Stage:** `cloud_storage` (position 14 in pipeline, already wired)

---

## Context

The `cloud_storage` pipeline stage and `CloudStorageAuditor` class already exist in
`workers/config_mgmt/tools/cloud_storage_auditor.py`, but the current implementation is a
low-quality stub using the old inline-Python-subprocess pattern (`build_command` returns
`python3 -c <script>`). All three coherence layers are already correctly wired:

- `pipeline.py` — `Stage("cloud_storage", [CloudStorageAuditor])`
- `playbooks.py` — `"cloud_storage"` present in `PIPELINE_STAGES["config_mgmt"]`
- `worker-stages.ts` — `{ stageName: "cloud_storage", sectionId: "WSTG-CONF-11" }`
- `concurrency.py` — `"cloud_storage_auditor": WeightClass.LIGHT`

**No changes are needed to any of these files.** The entire work is a rewrite of
`cloud_storage_auditor.py`, Dockerfile additions, and new unit tests.

---

## Objectives (from OWASP WSTG-CONF-11)

1. Identify cloud storage resources (S3 buckets, Azure Blob containers, GCS buckets)
   referenced by or associated with the target.
2. Assess whether access controls are properly enforced — unauthorized read, list, and
   write access should all be denied.
3. Confirm exploitability by probing list, read, and write access on every discovered
   resource, with non-destructive write probes (upload a labelled test file, delete on
   success).

---

## Approach: Extract → Enumerate → Scan (5 phases)

### Phase 1 — Extract (two sources, merged)

**Source A — DB assets:**
Query `Asset` WHERE `target_id = N` AND `asset_type IN ('url', 'subdomain', 'domain',
'cloud_storage')`. Apply regex patterns for all three providers to every `asset_value`.
This reuses discoveries from all 13 upstream pipeline stages for free.

**Source B — Live crawl** (aiohttp, concurrent):
`GET` homepage, `robots.txt`, `sitemap.xml`, and common JS paths
(`/static/js/`, `/assets/js/`, `/js/`). Apply the same regex patterns to each response body.

Both sources feed a single deduplication step producing:
- `s3_buckets: set[str]` — bare bucket names
- `azure_refs: set[tuple[str, str | None]]` — `(account, container | None)` pairs
- `gcs_buckets: set[str]` — bare bucket names

### Phase 2 — Enumerate (cloud_enum)

Run `cloud_enum -k <domain> -k <org_name>` where `org_name` is the second-level domain
label (e.g. `example` from `example.com`). `cloud_enum` generates bucket name mutations
from the supplied keywords across all three providers. Parse stdout to extract additional
S3, Azure, and GCS candidates. Merge into the Phase 1 sets.

### Phase 3 — S3 Scan (s3scanner)

Write deduplicated `s3_buckets` to a `NamedTemporaryFile`. Run:
```
s3scanner scan --bucket-file <file> --json-output <output>
```
Parse JSON output for `exists`, `listable`, `readable`, `writable` fields.

### Phase 4 — Azure Scan (azcopy + aiohttp)

For each `(account, container)` in `azure_refs`:
- If `container is None`: first enumerate containers via
  `GET https://<account>.blob.core.windows.net/?comp=list` (returns XML listing of
  public containers). For each discovered container name, add `(account, container)` to
  the work queue.
- Run `azcopy list https://<account>.blob.core.windows.net/<container>` to check
  anonymous list access.
- If list-accessible: issue aiohttp `PUT bbh-probe-<timestamp>.txt` with a 4-byte body.
  On `201` response, issue `DELETE` to clean up.
- If not list-accessible: issue aiohttp `HEAD` on a known common path
  (`/<account>.blob.core.windows.net/<container>/index.html`) to detect read-accessible
  but non-listable containers.

### Phase 5 — GCS Scan (aiohttp)

For each bucket in `gcs_buckets`:
- `GET https://storage.googleapis.com/<bucket>/?prefix=` — check for `ListBucketResult`
  XML in response body.
- If listable or `200`: issue `PUT https://storage.googleapis.com/<bucket>/bbh-probe-<ts>.txt`.
  On `200`/`200` response, issue `DELETE` to clean up.

---

## Component Design

### `workers/config_mgmt/tools/cloud_storage_auditor.py` (full rewrite)

Pattern: identical to `SubdomainTakeoverChecker` — `execute()` override,
`build_command`/`parse_output` raise `NotImplementedError`, all detection logic in pure
module-level functions.

#### Module-level constants

```python
_SECTION_ID = "WSTG-CONF-11"

# Compiled regex patterns (provider-specific)
_S3_PATTERNS: list[re.Pattern]
_AZURE_PATTERNS: list[re.Pattern]
_GCS_PATTERNS: list[re.Pattern]
```

#### Pure module-level functions

| Function | Input | Output |
|---|---|---|
| `_extract_storage_refs(body, provider)` | response/asset body str + `"s3"\|"azure"\|"gcs"` | `list[str]` raw matched strings |
| `_normalize_s3_ref(raw)` | raw S3 match | `(bucket_name: str, region: str\|None)` |
| `_normalize_azure_ref(raw)` | raw Azure match | `(account: str, container: str\|None)` |
| `_normalize_gcs_ref(raw)` | raw GCS match | `bucket_name: str` |
| `_parse_s3scanner_output(text)` | s3scanner JSON file text | `list[dict]` with keys `bucket`, `exists`, `listable`, `readable`, `writable` |
| `_classify_s3scanner_result(entry)` | one parsed s3scanner dict | `{"vulnerability": {...}}` or `{"observation": {...}}` or `None` |
| `_parse_cloud_enum_output(text)` | cloud_enum stdout | `{"s3": list[str], "azure": list[str], "gcs": list[str]}` |
| `_parse_azcopy_output(text)` | azcopy stdout | `list[dict]` with keys `container_url: str`, `accessible: bool` |
| `_classify_azure_probe(container_url, list_accessible, head_readable, write_status)` | probe results | `{"vulnerability": {...}}` or `{"observation": {...}}` or `None` |
| `_classify_gcs_probe(bucket_url, list_body, write_status)` | probe results | `{"vulnerability": {...}}` or `{"observation": {...}}` or `None` |
| `_classify_write_probe(url, provider, put_status)` | write probe result | `{"vulnerability": {...}}` or `None` |

All functions take only primitive types (str, int, dict). No I/O, no DB, no network —
fully unit-testable without mocking.

#### `execute()` flow

```
1.  cooldown check → early return
2.  acquire LIGHT semaphore
3.  emit TOOL_PROGRESS 0%
4.  parse target domain (urlparse → netloc)
5.  scope check → early return if out of scope

── Phase 1: Extract ──────────────────────────────────────────────
6.  query DB: Asset WHERE target_id=N
      AND asset_type IN ('url','subdomain','domain','cloud_storage')
7.  _extract_storage_refs() on each asset_value → collect refs
8.  aiohttp gather: GET homepage, robots.txt, sitemap.xml,
      /static/js/, /assets/js/, /js/
9.  _extract_storage_refs() on each response body → collect refs
10. _normalize_*() each ref → deduplicated:
      s3_buckets: set[str]
      azure_refs: set[tuple[str, str|None]]
      gcs_buckets: set[str]
11. emit TOOL_PROGRESS 20%

── Phase 2: Enumerate (cloud_enum) ──────────────────────────────
12. run_subprocess: cloud_enum -k <domain> -k <org_name>
13. _parse_cloud_enum_output() → merge into s3/azure/gcs sets
14. emit TOOL_PROGRESS 35%

── Phase 3: S3 Scan (s3scanner) ─────────────────────────────────
15. write s3_buckets → NamedTemporaryFile A
16. run_subprocess: s3scanner scan --bucket-file A --json-output B
17. _parse_s3scanner_output(B) → _classify_s3scanner_result() → all_findings
18. emit TOOL_PROGRESS 55%

── Phase 4: Azure Scan (azcopy + aiohttp) ───────────────────────
19. for each (account, container) in azure_refs:
      if container is None:
        aiohttp GET https://<account>.blob.core.windows.net/?comp=list
        → parse XML for container names → expand into (account, container) pairs
      run_subprocess: azcopy list https://<account>.blob.core.windows.net/<container>
      _parse_azcopy_output() → if list_accessible:
        aiohttp PUT bbh-probe-<ts>.txt → DELETE on 201
      else:
        aiohttp HEAD on common path → detect read-accessible container
      _classify_azure_probe(url, list_accessible, head_readable, write_status) → all_findings
20. emit TOOL_PROGRESS 70%

── Phase 5: GCS Scan (aiohttp) ──────────────────────────────────
21. for each bucket in gcs_buckets:
      aiohttp GET https://storage.googleapis.com/<bucket>/?prefix=
      if ListBucketResult in body:
        aiohttp PUT bbh-probe-<ts>.txt → DELETE on 200/201
      _classify_gcs_probe() → all_findings
22. emit TOOL_PROGRESS 85%

── Persist ──────────────────────────────────────────────────────
23. deduplicate all_findings by (location, name)
24. for each finding: _process_result() → scope check + DB insert
25. update job_state.last_tool_executed + last_seen
26. emit TOOL_PROGRESS 100%
27. return {found, in_scope, new, skipped_cooldown: False}
```

All temp files cleaned up in `finally` blocks. `FileNotFoundError` on any binary → log
warning, skip that phase. `asyncio.TimeoutError` per subprocess → log, skip phase.

---

## Severity Mapping

| Source | Condition | Severity |
|---|---|---|
| s3scanner | `writable: true` | `critical` |
| s3scanner | `listable: true` | `high` |
| s3scanner | `readable: true` only | `medium` |
| s3scanner | `exists: true`, fully restricted | observation |
| s3scanner | `exists: false` | observation (potential unclaimed bucket) |
| Azure / GCS | write probe PUT 201/200 | `critical` |
| Azure / GCS | list accessible | `high` |
| Azure / GCS | HEAD 200 (readable, not listable) | `medium` |
| Azure / GCS | exists but fully restricted | observation |

All vulnerabilities written with `section_id = "WSTG-CONF-11"` and
`worker_type = "config_mgmt"`.

---

## Dockerfile Changes (`docker/Dockerfile.config_mgmt`)

**Go builder stage** — add s3scanner alongside ffuf/subjack/nuclei:
```dockerfile
RUN go install github.com/sa7mon/s3scanner@latest
```

**azcopy** — downloaded as a tar.gz (pre-built binary, not a Go module):
```dockerfile
RUN wget -q -O /tmp/azcopy.tar.gz https://aka.ms/downloadazcopy-v10-linux && \
    tar -xzf /tmp/azcopy.tar.gz -C /tmp && \
    mv /tmp/azcopy_linux_amd64_*/azcopy /usr/local/bin/azcopy && \
    chmod +x /usr/local/bin/azcopy && \
    rm -rf /tmp/azcopy* || true
```

**Runtime stage** — copy s3scanner:
```dockerfile
COPY --from=go-builder /go/bin/s3scanner /usr/local/bin/
```

**Python deps** — add cloud-enum to pip install:
```dockerfile
RUN pip install --no-cache-dir cloud-enum aiohttp
```

The `|| true` guard on azcopy download prevents build failure when the network is
unavailable; the tool falls back to aiohttp probing for Azure.

---

## Error Handling Summary

| Failure mode | Behaviour |
|---|---|
| s3scanner binary missing | Log warning, skip Phase 3 |
| azcopy binary missing | Log warning, skip azcopy step; aiohttp fallback probes Azure via HTTP |
| cloud_enum missing | Log warning, skip Phase 2 |
| s3scanner timeout | Log warning, skip Phase 3 |
| azcopy timeout per container | Log warning, skip that container |
| DB query returns no assets | Phase 1 Source A produces empty sets; continue to live crawl |
| Live crawl page unreachable | Log warning, skip that URL; continue with remaining pages |
| No cloud refs found after Phases 1+2 | Return `{found:0, in_scope:0, new:0}` immediately |
| Write probe PUT succeeds, DELETE fails | Log warning; finding still reported as `critical` |
| Temp file cleanup | Always in `finally` block |

---

## New / Modified Files

### New files

| Path | Purpose |
|---|---|
| `workers/config_mgmt/tools/cloud_storage_auditor.py` | Full rewrite (replaces stub) |
| `tests/unit/config_mgmt/test_cloud_storage_auditor.py` | Pure-function unit tests |

### Modified files

| Path | Change |
|---|---|
| `docker/Dockerfile.config_mgmt` | Add s3scanner binary; download azcopy; pip install cloud-enum |

---

## Unit Tests (`tests/unit/config_mgmt/test_cloud_storage_auditor.py`)

All synchronous, no mocking, no DB, no subprocess, no network:

**`_extract_storage_refs`**
- S3 virtual-hosted pattern matches (`bucket.s3.amazonaws.com`)
- S3 path-style pattern matches (`s3.amazonaws.com/bucket`)
- Azure Blob pattern matches (`account.blob.core.windows.net`)
- GCS pattern matches (`storage.googleapis.com/bucket`)
- Non-matching body returns `[]`
- Multiple matches in one body returns all

**`_normalize_s3_ref`**
- Virtual-hosted style extracts bucket name and region
- Path-style extracts bucket name
- Website endpoint (`s3-website-us-east-1`) extracts bucket
- Invalid input returns `None`

**`_normalize_azure_ref`**
- `.blob.core.windows.net` extracts account name
- Path after hostname extracts container name
- Missing container returns `(account, None)`

**`_normalize_gcs_ref`**
- `storage.googleapis.com/<bucket>` extracts bucket name
- `<bucket>.storage.googleapis.com` extracts bucket name

**`_parse_s3scanner_output`**
- Empty or malformed JSON returns `[]`
- Writable bucket parsed correctly (`writable: true`)
- Listable-only bucket parsed correctly
- Non-existent bucket parsed correctly (`exists: false`)

**`_classify_s3scanner_result`**
- `writable: true` → `severity: "critical"`
- `listable: true`, `writable: false` → `severity: "high"`
- `readable: true` only → `severity: "medium"`
- `exists: true`, all false → observation dict
- `exists: false` → observation dict (potential unclaimed)
- Always sets `section_id: "WSTG-CONF-11"`

**`_parse_cloud_enum_output`**
- S3/Azure/GCS lines correctly bucketed by provider
- Unknown/malformed lines skipped
- Empty input returns `{"s3": [], "azure": [], "gcs": []}`

**`_parse_azcopy_output`**
- Accessible container parsed as `accessible: True`
- Permission-denied output parsed as `accessible: False`
- Empty output returns `[]`

**`_classify_azure_probe`**
- `list_accessible=True, head_readable=True, write_status=201` → `severity: "critical"`
- `list_accessible=True, head_readable=True, write_status=403` → `severity: "high"`
- `list_accessible=False, head_readable=False, write_status=201` → `severity: "critical"`
- `list_accessible=False, head_readable=True, write_status=403` → `severity: "medium"`
- `list_accessible=False, head_readable=False, write_status=403` → `None` (restricted, not interesting)
- Always sets `section_id: "WSTG-CONF-11"` on non-None results

**`_classify_gcs_probe`**
- `ListBucketResult` in body + write 200 → `severity: "critical"`
- `ListBucketResult` in body + write 403 → `severity: "high"`
- No listing + write 200 → `severity: "critical"`
- No listing + write 403 → `None`

**`_classify_write_probe`**
- PUT status 201 (S3 write success) → `severity: "critical"` vulnerability
- PUT status 200 (GCS write success) → `severity: "critical"` vulnerability
- PUT status 403 → `None`
- PUT status 404 → `None`

**`_SECTION_ID` constant**
- Equals `"WSTG-CONF-11"`

---

## What Does Not Change

- `pipeline.py` — no change
- `playbooks.py` — no change
- `worker-stages.ts` — no change
- `concurrency.py` — no change
- `tools/__init__.py` — no change
- `base_tool.py` — no change
