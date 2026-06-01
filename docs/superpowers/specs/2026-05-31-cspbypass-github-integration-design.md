---
title: CSPBypass GitHub Integration Design
date: 2026-05-31
worker: config_mgmt
wstg: WSTG-CONF-12
---

# CSPBypass GitHub Integration

Replace the `cspbypass` pip package with an in-process Python lookup backed by
`data.tsv` from [renniepak/CSPBypass](https://github.com/renniepak/CSPBypass).

## Background

The current `csp_tester.py` runs Layer 3 CSP analysis by shelling out to a
`cspbypass` binary installed from PyPI. The `renniepak/CSPBypass` repository is
a static web app whose entire value lives in two artifacts:

- `data.tsv` — a two-column tab-separated lookup table: `domain\tcode`, where
  `code` is an HTML/JS payload demonstrating a JSONP/callback bypass for that
  domain.
- ~30 lines of JS matching logic — parses a CSP string, extracts allowed
  hostnames, finds rows in the TSV whose domain is covered by those hostnames.

The matching algorithm is simple enough to port to Python directly, eliminating
the subprocess entirely.

## Goals

1. Remove the `cspbypass` pip dependency from `requirements.txt` and the
   Dockerfile.
2. Bake `data.tsv` into the Docker image at build time.
3. Replace `_run_csp_bypass(url)` with a synchronous in-process function
   `_match_csp_bypasses(csp_header, url)` that produces identical output.
4. Keep the vulnerability dict format unchanged so no downstream consumers are
   affected.

## Architecture

### Data acquisition

`data.tsv` is downloaded once at Docker build time:

```dockerfile
RUN mkdir -p /cspbypass && \
    wget -q -O /cspbypass/data.tsv \
    https://raw.githubusercontent.com/renniepak/CSPBypass/main/data.tsv
```

The file is read into module-level `_BYPASS_DB: list[tuple[str, str]]` when
`csp_tester.py` is first imported. If the file is absent, a warning is logged
and `_BYPASS_DB` is set to `[]` so the worker degrades gracefully.

### Matching logic (Python port of JS)

Three helper functions replace the subprocess:

#### `_parse_csp_source(token: str) -> dict | None`

Parses a single CSP source token into structured fields:

| Field | Example | Notes |
|-------|---------|-------|
| `scheme` | `"https"` | `None` if no scheme specified |
| `host` | `"ajax.googleapis.com"` | port stripped |
| `wildcard_subdomain` | `True` | token was `*.example.com` |
| `path_prefix` | `"/gtag/js"` | `None` if no path |

Returns `None` for bare-scheme tokens (e.g. `https:`) — these match any host
and are skipped (too broad to produce meaningful gadget matches).

#### `_matches_csp_source(gadget_domain: str, gadget_code: str, src: dict) -> bool`

Three-step validation mirroring the JS `matchesCspSource`:

1. **URL extraction** — parse `src=` or `href=` from `gadget_code`; fall back
   to `https://{gadget_domain}`.
2. **Scheme** — enforced only when `src["scheme"]` is set.
3. **Host** — `src["host"] == "*"` matches any host; `wildcard_subdomain` uses
   `gadget_url_host.endswith("." + src["host"])`; otherwise exact match.
4. **Path prefix** — when `src["path_prefix"]` is set, enforce segment-boundary
   prefix: `gadget_path == prefix` or `gadget_path.startswith(prefix + "/")`.

#### `_match_csp_bypasses(csp_header: str, url: str) -> list[dict]`

1. Parse `csp_header` with the existing `_parse_csp_header()`.
2. Extract `script-src` tokens (fall back to `default-src`).
3. Filter keywords: `'self'`, `'unsafe-inline'`, `'unsafe-eval'`, `'none'`,
   `'strict-dynamic'`, `'wasm-unsafe-eval'`, `'report-sample'`, and any token
   matching `'nonce-*'` or `'sha(256|384|512)-*'`.
4. Call `_parse_csp_source()` on each remaining token.
5. For each `(domain, code)` in `_BYPASS_DB`, call `_matches_csp_source()`.
6. Deduplicate by `(domain, code)` before returning.
7. Return each match as:
   ```python
   {"vulnerability": {
       "name": f"CSP bypass gadget: {domain} on {url}",
       "severity": "high",
       "description": f"renniepak/CSPBypass: domain '{domain}' in script-src "
                      f"has a known bypass gadget on {url}. Payload: {code}",
       "location": url,
       "section_id": "WSTG-CONF-12",
   }}
   ```

### Call site change

`_probe_url()` already holds `csp_header`. Line 335 changes from:

```python
results.extend(await _run_csp_bypass(url))
```

to:

```python
results.extend(_match_csp_bypasses(csp_header, url))
```

No `await` — the function is synchronous.

## Files changed

| File | Change |
|------|--------|
| `docker/Dockerfile.config_mgmt` | Remove `cspbypass` from `pip install`; add `wget` of `data.tsv` |
| `workers/config_mgmt/requirements.txt` | Remove `cspbypass>=0.1.0` |
| `workers/config_mgmt/tools/csp_tester.py` | Replace `_run_csp_bypass` with `_match_csp_bypasses` and helpers; add module-level TSV loader |

No other files are affected. The three-layer pipeline structure in `_probe_url()`
is preserved; only the implementation of Layer 3 changes.

## Error handling

- Missing `/cspbypass/data.tsv`: log `WARNING` at import, set `_BYPASS_DB = []`,
  Layer 3 silently returns no findings.
- Malformed TSV row: skip the row, log `DEBUG`.
- Unparseable gadget URL: fall back to `https://{domain}` before matching.

## Testing

- Unit test `_parse_csp_source` against known tokens (wildcard, path, scheme,
  bare host).
- Unit test `_match_csp_bypasses` with a synthetic TSV and a CSP string that
  should produce exactly one match and one non-match.
- Verify `_BYPASS_DB` loads correctly from a fixture TSV file.
