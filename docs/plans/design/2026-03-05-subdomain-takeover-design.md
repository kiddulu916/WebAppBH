# Subdomain Takeover Stage — Design Document

**Date:** 2026-03-05
**Phase:** 4 (recon-core)
**Status:** Draft

## 1. Overview

Add a new pipeline stage to recon-core that detects subdomain takeover vulnerabilities using **subjack**. The stage runs after DNS resolution (Stage 3) and before fingerprinting, checking all discovered domains for dangling CNAME records pointing to unclaimed external services.

## 2. Tool: SubjackTool

### Pattern

Follows the input-file pattern used by Massdns and Naabu:
- Queries all `Asset(target_id=X, asset_type='domain')` from the database
- Writes domains to a temporary file
- Runs subjack against the file
- Parses JSON output
- Cleans up the temp file

### Properties

| Property       | Value                |
|----------------|----------------------|
| `name`         | `"subjack"`          |
| `weight_class` | `WeightClass.LIGHT`  |

### Command

```
subjack -w <input_file> -t 50 -timeout 30 -o /dev/stdout -ssl -a /opt/fingerprints.json
```

| Flag       | Purpose                                      |
|------------|----------------------------------------------|
| `-w`       | Input file containing subdomains             |
| `-t 50`    | Concurrent threads                           |
| `-timeout` | Per-request timeout (seconds)                |
| `-o`       | Output to stdout for capture                 |
| `-ssl`     | Also check HTTPS variants                    |
| `-a`       | Path to fingerprints.json (service signatures)|

### Output Format

Subjack outputs JSON lines:
```json
{"subdomain": "blog.example.com", "vulnerable": true, "service": "github", "fingerprint": "There isn't a GitHub Pages site here."}
```

### parse_output() Behavior

1. Split stdout by newlines
2. Parse each line as JSON
3. Filter to only `"vulnerable": true` entries
4. Return list of dicts: `{"subdomain": str, "service": str, "fingerprint": str}`

### Result Handling (execute override)

For each vulnerable result:
1. Scope-check the subdomain via `scope_manager.is_in_scope()`
2. Look up the existing `Asset` row for that subdomain
3. Insert an `Observation` row:
   - `tech_stack`: `["subjack:takeover"]`
   - `page_title`: `"Subdomain takeover: {service}"`
   - `status_code`: `None`
4. Insert a critical `Alert`:
   - `alert_type`: `"critical"`
   - `message`: `"Subdomain takeover possible: {subdomain} → {service} (CNAME dangling)"`
5. Push alert event to Redis `events:{target_id}` stream

## 3. Pipeline Changes

### New Stage Order (7 stages)

```python
STAGES = [
    Stage("passive_discovery",    [Subfinder, Assetfinder, Chaos, AmassPassive]),
    Stage("active_discovery",     [Sublist3r, Knockpy, AmassActive]),
    Stage("liveness_dns",         [Massdns, HttpxTool]),
    Stage("subdomain_takeover",   [SubjackTool]),                    # NEW
    Stage("fingerprinting",       [Webanalyze]),
    Stage("port_mapping",         [Naabu]),
    Stage("deep_recon",           [Katana, Hakrawler, Waybackurls, Gauplus, Paramspider]),
]
```

### Resumability

- The pipeline resumes by matching `job_state.current_phase` against stage names (strings, not indices)
- The new stage name `"subdomain_takeover"` is unique and does not conflict
- Existing in-progress jobs that passed `"liveness_dns"` will correctly skip to `"fingerprinting"`
- No data migration required

### SSE Events

The existing `stage_complete` event mechanism works automatically:
```json
{"event": "stage_complete", "stage": "subdomain_takeover", "stats": {"found": 2, "in_scope": 2, "new": 2}}
```

## 4. Docker Changes

### Dockerfile

```dockerfile
# Install subjack
RUN go install github.com/haccer/subjack@latest \
    && cp /root/go/bin/subjack /usr/local/bin/subjack

# Copy fingerprints.json
RUN cp /root/go/pkg/mod/github.com/haccer/subjack@*/fingerprints.json /opt/fingerprints.json
```

### Dependencies

No Python package changes — subjack is a standalone Go binary. The tool wrapper uses only stdlib imports (`json`, `tempfile`, `os`) plus existing `lib_webbh` modules.

### Fingerprints

`fingerprints.json` contains service signatures for GitHub Pages, Heroku, AWS S3, Shopify, Tumblr, etc. Baked into the Docker image at `/opt/fingerprints.json`. Updated by rebuilding the image.

## 5. Files to Create/Modify

| File | Action |
|------|--------|
| `workers/recon_core/tools/subjack.py` | Create — SubjackTool class |
| `workers/recon_core/tools/__init__.py` | Modify — add `SubjackTool` export |
| `workers/recon_core/pipeline.py` | Modify — insert `subdomain_takeover` stage at index 3 |
| `docker/Dockerfile.recon-core` | Modify — add subjack installation |
| `workers/recon_core/tests/test_subjack.py` | Create — unit + integration tests |

## 6. Testing Strategy

### Unit Tests

| Test | Description |
|------|-------------|
| `test_build_command` | Verify command includes `-w`, `-ssl`, `-a /opt/fingerprints.json`, temp file path |
| `test_parse_output_vulnerable` | Sample JSON with `vulnerable: true` → parsed dicts with subdomain, service, fingerprint |
| `test_parse_output_not_vulnerable` | `vulnerable: false` entries filtered out → empty list |
| `test_parse_output_empty` | Empty stdout → empty list |
| `test_parse_output_malformed` | Malformed JSON lines skipped gracefully |

### Integration Tests

| Test | Description |
|------|-------------|
| `test_execute_creates_alert` | Mock subprocess → verify `Alert(alert_type='critical')` inserted |
| `test_execute_creates_observation` | Mock subprocess → verify `Observation` row created on matching `Asset` |
| `test_execute_skips_out_of_scope` | Out-of-scope subdomain → no alert/observation created |
| `test_pipeline_stage_order` | `"subdomain_takeover"` at index 3 in STAGES |

## 7. Data Flow

```
Stage 3 (liveness_dns)
    ↓ domains stored in Asset table
Stage 4 (subdomain_takeover)
    ↓ SubjackTool queries Asset(asset_type='domain')
    ↓ writes to temp file → runs subjack → parses JSON
    ↓ for each vulnerable subdomain:
    ↓   scope check → lookup Asset → insert Observation + Alert
    ↓ pushes alert events to Redis
Stage 5 (fingerprinting)
    ↓ continues normally
```
