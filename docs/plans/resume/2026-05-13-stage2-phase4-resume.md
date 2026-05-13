# Resume Prompt — Stage 2 (WSTG-INFO-02) Phase 4

> Paste this entire document as the opening message of a new Claude Code
> session to resume the Stage 2 rebuild at Phase 4.

---

## Context

You are resuming a multi-phase rebuild of the `info_gathering` worker's Stage 2
(`web_server_fingerprint`, OWASP WSTG-INFO-02). The design and implementation
plan are durable on disk; phases 0–3 are merged on `main`. We paused after
Phase 3 so the user could review and so memory could be persisted.

**Working directory:** `/home/kiddulu/Projects/WebAppBH` (branch `main`).

**Authoritative docs (read these first):**

- Design: `docs/plans/design/2026-05-11-info-gathering-stage2-fingerprint-design.md`
- Implementation plan: `docs/plans/implementation/2026-05-11-info-gathering-stage2-fingerprint.md`
- This resume doc: `docs/plans/resume/2026-05-13-stage2-phase4-resume.md`

**Memory pointer:** `project_stage2_fingerprint.md` in the auto-memory dir.

---

## What's already built (Phases 0–3, 37 commits)

### Phase 0 — Preconditions on `InfoGatheringTool`

- `save_observation` call sites fixed in `httpx.py` and `whatweb.py` (were
  passing `target_id` positionally instead of `asset_id` kwarg — broken).
- `Httpx` repurposed as a single-host probe (no more DB fan-out).
- `save_location(asset_id, port, protocol, service, state) -> int` upsert
  helper added to `InfoGatheringTool`.
- `resolve_or_create_asset(target_id, host, base_domain) -> int` helper:
  detects IP/domain/subdomain, upserts Asset row, raises `ValueError` on
  empty host, handles IPv6 `%scope` suffix. Uses `source_tool="pipeline_preamble"`.
- Abstract `execute` return type widened to `dict[str, Any] | None`.
- Module-level `PIPELINE_PREAMBLE_SOURCE` constant.

### Phase 1 — `FingerprintAggregator` + signatures

`workers/info_gathering/fingerprint_aggregator.py`:
- `ProbeResult` dataclass: `probe`, `obs_id`, `signals`, `error`.
- `WEIGHTS` table (9 signal sources with floats).
- `SLOTS = ("edge", "origin_server", "framework", "os", "tls", "waf")`.
- `Intensity = Literal["low", "medium", "high"]`.
- `FingerprintAggregator(asset_id, target_id, intensity)`:
  - `_score_slot(slot, results)` — weighted scoring with conflict detection.
    Three return shapes (single decisive vendor / conflict with `candidates` /
    null with all signals). **Consumers must branch on `slot["conflict"]`
    before reading `slot["signals"]`** — the conflict branch has no `signals`
    key.
  - `write_summary(results) -> int` — writes one Observation
    `_probe="summary"` with full fingerprint, `partial: True` if any probe
    errored, `raw_probe_obs_ids` list. Skips `tls` in the slot loop and lets
    `_merge_tls` own that key.
  - `emit_info_leaks(fingerprint, raw) -> list[int]` — emits up to 4 vulns:
    server+version disclosure (INFO), X-Powered-By (INFO), default error
    page (LOW), internal debug header (LOW). Per-probe keys may be missing
    when that probe errored — `or {}` defaults are load-bearing.
  - `_save_summary_observation(*, payload)` and `_save_vuln(*, ...)` —
    keyword-only.

`workers/info_gathering/fingerprint_signatures.py`: `DEFAULT_ERROR_LEAKERS`,
`INTERNAL_DEBUG_HEADERS`, `WAF_PASSIVE_PATTERNS` (typed via `WafPattern`
TypedDict), `CDN_CERT_ISSUERS`.

### Phase 2 — Eight probe units in `workers/info_gathering/tools/`

Each returns `ProbeResult`. All accept `target_id`, `host`, `asset_id`,
`intensity`, `rate_limiter` via kwargs. Missing `host`/`asset_id` returns
`ProbeResult(error="missing host or asset_id", obs_id=None)`. Backing-call
failures return `ProbeResult(error=str(exc))` rather than raising.

| Probe | File | _probe key | Notes |
|---|---|---|---|
| `LivenessProbe` | `liveness_probe.py` | `liveness` | shells `httpx` over 8 ports; writes Location rows |
| `BannerProbe` | `banner_probe.py` | `banner` | aiohttp GET; truncates header values >4 KiB |
| `HeaderOrderProbe` | `header_order_probe.py` | `header_order` | raw TLS socket; cert verify off |
| `MethodProbe` | `method_probe.py` | `method_probe` | intensity-gated; methods sent via `asyncio.gather` |
| `ErrorPageProbe` | `error_page_probe.py` | `error_page` | random `secrets.token_hex(8)` path; SHA-256 body |
| `TLSProbe` | `tls_probe.py` | `tls` | shells `tlsx`; emits `tls_summary` non-slot signal |
| `WAFProbe` | `waf_probe.py` | `waf` | passive always; `wafw00f` at medium/high; logs failures |
| `WhatWeb` (refactored) | `whatweb.py` | `app_fingerprint` | plugin → slot via `_PLUGIN_SLOTS`; `-a 3` at high only |

Two bugs caught and fixed during Phase 2 review (commit `f709c9e`):
- ErrorPageProbe: `_SIGNATURES` had `"Apache"` before `"Apache Tomcat"` →
  Tomcat misclassified. Reordered most-specific first.
- HeaderOrderProbe: `_is_title_dashed` failed on single-letter parts
  (`X-Cache`, `X-Frame-Options` etc.) because `"".islower()` is False. Fixed
  with `(not p[1:] or p[1:].islower())`.

### Phase 3 — Pipeline wiring (`workers/info_gathering/pipeline.py`)

- `Pipeline.run()` preamble: `_select_host(target)` → `_resolve_subject_asset(host)`
  → `_get_intensity(playbook)`. Asset resolved once per run; `asset_id`,
  `host`, `intensity` threaded through every `_run_stage` call.
- `_run_stage(stage, target, *, scope_manager, headers, rate_limiter,
  asset_id, host, intensity)` returns a **list** of per-tool results (mixed
  `ProbeResult` for Stage 2 and legacy dicts elsewhere).
- After any stage with `section_id == "4.1.2"`:
  `FingerprintAggregator(asset_id, target_id, intensity)` → `write_summary` →
  `_stage2_raw_from_results` → `emit_info_leaks`. SSE event stats include
  `probes`, `summary_written`, `vulns`.
- `STAGES[1]` (`web_server_fingerprint`, `4.1.2`) tool list now:
  `[LivenessProbe, BannerProbe, HeaderOrderProbe, MethodProbe,
  ErrorPageProbe, TLSProbe, WAFProbe, WhatWeb]`. `Nmap` removed (moved to
  Stage 9 per the design).
- `concurrency.py`'s `TOOL_WEIGHTS`: orphan `Nmap` removed; 7 new probes
  added as `LIGHT`.

### Test state

107 passing tests across:
```
tests/test_fingerprint_aggregator.py        (27)
tests/test_stage2_banner_probe.py            (5)
tests/test_stage2_error_page_probe.py        (7)
tests/test_stage2_header_order_probe.py      (5)
tests/test_stage2_liveness_probe.py          (5)
tests/test_stage2_method_probe.py            (5)
tests/test_stage2_pipeline_wiring.py         (6)
tests/test_stage2_tls_probe.py               (5)
tests/test_stage2_waf_probe.py               (5)
tests/test_stage2_whatweb_probe.py           (7)
tests/test_info_gathering_base_tool.py      (13)
tests/test_rate_limiter_pipeline.py          (5)
tests/test_info_gathering/                   (8)
tests/test_pipeline_stage1.py                (3)
```

Run them with:
```bash
pytest tests/test_fingerprint_aggregator.py tests/test_stage2_*.py \
  tests/test_info_gathering_base_tool.py tests/test_rate_limiter_pipeline.py \
  tests/test_info_gathering/ tests/test_pipeline_stage1.py
```

Pre-existing failures elsewhere (`test_api_contract.py`, `test_bounty_tracker.py`,
`test_client_side/test_pipeline.py`, etc.) are unrelated to Stage 2 work.

### Shared test helpers

`tests/_stage2_helpers.py` exposes `fake_session(headers=..., status=...,
body=..., cookies=..., exception=...)` and a `FakeHeaders` dict-subclass
that satisfies aiohttp's `getall("Set-Cookie", default)` API. Reuse for any
new aiohttp-mocking tests in Phases 4–7.

---

## What's left

### Phase 4 — Playbook config + Docker (small)

Implementation plan reference: `docs/plans/implementation/2026-05-11-info-gathering-stage2-fingerprint.md`
sections 4.1 / 4.2.

**Task 4.1: Lock the `fingerprint_intensity` playbook contract.**

Create `tests/test_playbook_stage2_intensity.py`. The pipeline already reads
`config.fingerprint_intensity` via `Pipeline._get_intensity`; this test
pins the contract from the playbook side. Two tests:
- Default `"low"` when `config` omits the field.
- Explicit `"high"` flows through `get_worker_stages` unchanged.

No code change needed in `shared/lib_webbh/playbooks.py` — `_get_intensity`
in `pipeline.py` already handles the read. Just lock the shape so future
playbook refactors don't break Stage 2 silently. Commit message:
`test(stage2): lock playbook fingerprint_intensity contract`.

**Task 4.2: Install `tlsx` and `wafw00f` in the info_gathering image.**

Modify `docker/Dockerfile.info_gathering`:
- Add a `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` block
  with `mv /root/go/bin/tlsx /usr/local/bin/tlsx`.
- Add `pip install --no-cache-dir wafw00f==2.2.0`.

Verify by building: `docker build -f docker/Dockerfile.info_gathering -t
test-stage2-image .` then `docker run --rm test-stage2-image which tlsx
wafw00f`. Expected: both paths printed. Commit message: `build(stage2):
install tlsx and wafw00f in info_gathering image`.

**Reviewer pattern:** Phase 4 is small enough to skip the implementer +
2-reviewer loop and run inline. Recommend a single inline pass.

### Phase 5 — Integration tests (the big lift)

14 integration tests in `tests/test_info_gathering_stage2_integration.py`
exercising the full pipeline preamble → tools → aggregator → DB writes →
SSE event path. Use in-memory aiosqlite + fakeredis. See plan §4.4 for
the I1–I14 list. Reference fixture skeleton:
`tests/fixtures/stage2/cloudflare_responses.py`.

Each integration test follows: write failing test → run → adjust → commit.
One commit per test (`test(stage2): I<N> <description>`).

### Phase 6 — Dashboard

- `dashboard/src/components/campaign/PlaybookSelector.tsx`: intensity radio
  with three options. The exact warning copy lives in design §2.2 — use
  verbatim:
  - **Low**: "Conservative probes that look like normal client variation.
    Safe against most production targets."
  - **Medium**: "⚠️ Adds active WAF probing and uncommon HTTP methods
    (PROPFIND, TRACE, HTTP/0.9). May appear in IDS/WAF logs as suspicious.
    Use when target authorization clearly covers active reconnaissance."
  - **High**: "⚠️⚠️ Sends malformed methods, garbage verbs, and aggressive
    plugin checks. Will trigger WAFs, may be blocked, and is conspicuous to
    defenders. Only use against authorized targets with explicit go-ahead
    for noisy fingerprinting."
  Description is shown only when the option is focused/selected.
- New `dashboard/src/components/c2/FingerprintPanel.tsx` rendered inside
  `AssetDetailDrawer.tsx` when the selected Asset has a `_probe="summary"`
  Observation.
- 8 Playwright e2e specs in `dashboard/e2e/stage2-fingerprint.spec.ts` —
  see plan §4.5 for E1–E8.

### Phase 7 — Verification + PR

Full test sweep, smoke run via `docker compose up`, then PR.

---

## Conventions you must keep

These are project rules surfaced by reviewers across Phases 0–3:

1. **Test discipline.** Every code change ships with a failing test first,
   then the implementation, then commit. `@pytest.mark.anyio` on async tests
   (`anyio_backend = "asyncio"` is auto-loaded from `tests/conftest.py`).
2. **Commit cadence.** One logical change per commit. Conventional commit
   prefixes used so far: `feat(stage2):`, `fix(stage2):`, `test(stage2):`,
   `refactor(stage2):`, `build(stage2):`.
3. **No comments unless WHY is non-obvious.** Project rule from `CLAUDE.md`.
   Description comments rot; rationale comments earn their keep.
4. **Don't validate at internal boundaries.** Only validate at system
   boundaries (user input, external APIs, subprocess output). The pipeline
   preamble owns the contract for what reaches the aggregator's `raw` dict.
5. **Stage 2 probes return `ProbeResult`, not exceptions.** Backing-call
   failures become `ProbeResult(error=str(exc), obs_id=None)`. The
   aggregator filters errored results from scoring but still tracks them in
   `partial: True`.
6. **Pre-existing pyright noise** about `lib_webbh` imports not resolving is
   an IDE config issue across the whole repo. Ignore it — tests pass at
   runtime.
7. **Subagent reviewers** for spec compliance + code quality consistently
   catch real issues. Use them per task when capacity allows. Use the
   `general-purpose` agent for spec compliance and `code-reviewer` for
   quality, with verbatim canonical content blocks for the reviewer to
   check against.
8. **Naming consistency between `ProbeResult.probe` and Observation `_probe`.**
   Established in Phase 2 review (commit `565c730`). Don't drift.

---

## How to start the next session

1. Read this resume doc + the design doc + the implementation plan.
2. Run the pytest command from "Test state" above to confirm the 107 tests
   still pass (anchor point).
3. Begin Phase 4. Recommend: `TaskCreate` for each Phase 4 task,
   `TaskUpdate in_progress` before starting, `completed` when each commit
   lands.
4. After Phase 4, decide whether to bundle Phase 5 integration tests with
   per-task subagent reviews (slow, thorough) or inline (faster, less
   coverage of design corner-cases).

Have fun. The hard parts are done — Phases 4–7 are mostly mechanical.
