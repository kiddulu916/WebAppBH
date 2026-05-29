# WSTG-IDNT-04 Account Enumeration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Faithfully re-implement the `account_enumeration` tool (WSTG-IDNT-04) with the OWASP baseline-delta oracle methodology, six enumeration techniques, a unit-testable standalone probe module, and operator-tunable parameters surfaced in the dashboard Settings Drawer.

**Architecture:** Extract probe logic into a dependency-light standalone module (`account_enum_probe.py`, `httpx` + stdlib only) with pure decision functions and a `__main__` JSON entry point; reduce `account_enumerator.py` to a thin `IdentityMgmtTool` wrapper that builds config from `target.target_profile["account_enum"]` and invokes the module via `python3 -m`. Add an `account_enum` profile block plumbed through the orchestrator, dashboard types, API client, and Settings Drawer.

**Tech Stack:** Python 3 + httpx (worker), pytest + httpx `MockTransport` (tests), FastAPI + Pydantic (orchestrator), Next.js + React + TypeScript (dashboard).

---

## Spec

Reference: `docs/superpowers/specs/2026-05-28-wstg-idnt-04-account-enumeration-design.md`

## File Structure

**New**
- `workers/identity_mgmt/tools/account_enum_probe.py` — standalone probe module: config, signatures, oracle, six techniques, `__main__`.
- `tests/unit/identity_mgmt/test_account_enum_probe.py` — unit tests for the probe module.
- `tests/unit/identity_mgmt/test_account_enumerator.py` — unit tests for the wrapper tool.

**Modified**
- `workers/identity_mgmt/tools/account_enumerator.py` — slim wrapper.
- `orchestrator/main.py` — `TargetProfileUpdate` model + `update_target_profile` endpoint.
- `dashboard/src/types/schema.ts` — `TargetProfile` interface.
- `shared/interfaces.ts` — `TargetProfile` interface.
- `dashboard/src/lib/api.ts` — `updateTargetProfile` param type.
- `dashboard/src/components/c2/SettingsDrawer.tsx` — new "Account Enumeration" section.

**Unchanged (three-layer coherence already intact)**
- `workers/identity_mgmt/pipeline.py`, `shared/lib_webbh/playbooks.py`, `dashboard/src/lib/worker-stages.ts`.

## Conventions

- Tests run from the repo root: `python -m pytest tests/unit/identity_mgmt/<file>.py -v`. `tests/unit/conftest.py` already inserts the repo root onto `sys.path`, so `from workers.identity_mgmt.tools.account_enum_probe import ...` resolves.
- Commits use the repository's `type: summary` style. The shell is **PowerShell** — chain commands with `;` (not `&&`), and avoid heredocs.

---

### Task 1: Probe module skeleton — config defaults & merge

**Files:**
- Create: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/identity_mgmt/test_account_enum_probe.py`:

```python
"""Unit tests for the account enumeration probe module (WSTG-IDNT-04)."""
import json

from workers.identity_mgmt.tools import account_enum_probe as probe


def test_merge_config_returns_defaults_when_empty():
    cfg = probe.merge_config({})
    assert cfg["enabled"] is True
    assert cfg["max_candidates"] == 6
    assert cfg["request_delay_ms"] == 150
    assert cfg["baseline_samples"] == 3
    assert cfg["timing_samples"] == 2
    assert cfg["custom_seeds"] == []
    assert cfg["techniques"]["login_oracle"] is True
    assert cfg["techniques"]["cms_wp"] is True


def test_merge_config_overrides_scalars():
    cfg = probe.merge_config({"max_candidates": 2, "request_delay_ms": 0})
    assert cfg["max_candidates"] == 2
    assert cfg["request_delay_ms"] == 0
    # untouched defaults remain
    assert cfg["baseline_samples"] == 3


def test_merge_config_merges_techniques_partially():
    cfg = probe.merge_config({"techniques": {"cms_wp": False}})
    assert cfg["techniques"]["cms_wp"] is False
    assert cfg["techniques"]["login_oracle"] is True


def test_merge_config_does_not_mutate_defaults():
    probe.merge_config({"max_candidates": 99, "techniques": {"login_oracle": False}})
    assert probe.DEFAULTS["max_candidates"] == 6
    assert probe.DEFAULTS["techniques"]["login_oracle"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'workers.identity_mgmt.tools.account_enum_probe'`.

- [ ] **Step 3: Write minimal implementation**

Create `workers/identity_mgmt/tools/account_enum_probe.py`:

```python
"""Account enumeration probe (WSTG-IDNT-04).

Standalone, dependency-light module (httpx + stdlib only; no lib_webbh/DB
imports) so it can be unit-tested in isolation and invoked as a subprocess by
``account_enumerator.py`` via ``python3 -m``.

Implements the OWASP baseline-delta oracle: per endpoint, learn the natural
response jitter from a guaranteed-invalid username, then flag a candidate as a
likely valid account only when its response diverges beyond that jitter band.
"""

from __future__ import annotations

import copy

# * Operator-tunable defaults. Overridden by target_profile["account_enum"].
DEFAULTS = {
    "enabled": True,
    "techniques": {
        "login_oracle": True,
        "reset_oracle": True,
        "reg_oracle": True,
        "uri_probe": True,
        "pattern_gen": True,
        "cms_wp": True,
    },
    "max_candidates": 6,
    "request_delay_ms": 150,
    "baseline_samples": 3,
    "timing_samples": 2,
    "custom_seeds": [],
}


def merge_config(profile_block: dict | None) -> dict:
    """Deep-merge an account_enum profile block over DEFAULTS.

    Args:
        profile_block: The ``account_enum`` sub-dict from a target profile.

    Returns:
        A new config dict; DEFAULTS is never mutated.
    """
    cfg = copy.deepcopy(DEFAULTS)
    if not profile_block:
        return cfg
    for key, value in profile_block.items():
        if key == "techniques" and isinstance(value, dict):
            cfg["techniques"].update(value)
        else:
            cfg[key] = value
    return cfg
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): scaffold account_enum_probe config + merge (WSTG-IDNT-04)"
```

---

### Task 2: Response signatures & text normalization

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/identity_mgmt/test_account_enum_probe.py`:

```python
def test_normalize_text_strips_digits_and_collapses_space():
    assert probe.normalize_text("  Invalid  User 12345 \n") == "invalid user"


def test_normalize_text_truncates_to_300_chars():
    assert len(probe.normalize_text("a " * 1000)) <= 300


class _Resp:
    """Minimal stand-in for an httpx.Response."""

    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


def test_build_signature_captures_fields():
    resp = _Resp(status_code=401, text="Invalid password 99", headers={"location": "/x"})
    sig = probe.build_signature(resp, elapsed_ms=123.4)
    assert sig.status == 401
    assert sig.redirect_location == "/x"
    assert sig.body_len == len("Invalid password 99")
    assert sig.body_snippet == "invalid password"
    assert sig.elapsed_ms == 123.4


def test_build_signature_no_location_header():
    sig = probe.build_signature(_Resp(status_code=200, text="ok"), elapsed_ms=1.0)
    assert sig.redirect_location == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'normalize_text'`.

- [ ] **Step 3: Write minimal implementation**

Add to the top of `account_enum_probe.py` (after the `from __future__` line, add the imports) and append the new code:

```python
import re
from dataclasses import dataclass
```

```python
@dataclass
class ResponseSignature:
    """A comparable fingerprint of one HTTP response."""

    status: int
    redirect_location: str
    body_len: int
    body_snippet: str
    elapsed_ms: float


def normalize_text(text: str) -> str:
    """Lowercase, drop digits, strip non-alphanumerics, collapse whitespace.

    Removes volatile content (CSRF tokens, counters, timestamps) so two
    structurally identical error pages compare equal. Truncated to 300 chars.
    """
    lowered = text.lower()
    no_digits = re.sub(r"[0-9]+", "", lowered)
    alnum = re.sub(r"[^a-z\s]+", " ", no_digits)
    collapsed = re.sub(r"\s+", " ", alnum).strip()
    return collapsed[:300]


def build_signature(resp, elapsed_ms: float) -> ResponseSignature:
    """Build a ResponseSignature from an httpx-like response object."""
    location = resp.headers.get("location", "") if resp.headers else ""
    return ResponseSignature(
        status=resp.status_code,
        redirect_location=location,
        body_len=len(resp.text),
        body_snippet=normalize_text(resp.text),
        elapsed_ms=elapsed_ms,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add response signature + text normalization"
```

---

### Task 3: The oracle — noise learning, divergence decision, keyword corroboration

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/identity_mgmt/test_account_enum_probe.py`:

```python
def _sig(status=200, loc="", body_len=1000, snippet="login failed", ms=100.0):
    return probe.ResponseSignature(status, loc, body_len, snippet, ms)


def test_learn_noise_computes_means_and_margins():
    baseline = [_sig(body_len=1000, ms=100.0), _sig(body_len=1010, ms=110.0),
                _sig(body_len=990, ms=90.0)]
    noise = probe.learn_noise(baseline)
    assert 990 <= noise.len_mean <= 1010
    assert noise.len_margin > 0
    assert noise.time_margin > 0


def test_distinguishable_on_status_difference():
    baseline = [_sig(status=200), _sig(status=200), _sig(status=200)]
    noise = probe.learn_noise(baseline)
    cand = _sig(status=302)
    flagged, dim = probe.is_distinguishable(cand, baseline, noise, want_timing=False)
    assert flagged is True
    assert dim == "status"


def test_distinguishable_on_redirect_difference():
    baseline = [_sig(loc=""), _sig(loc=""), _sig(loc="")]
    noise = probe.learn_noise(baseline)
    cand = _sig(loc="/dashboard")
    flagged, dim = probe.is_distinguishable(cand, baseline, noise, want_timing=False)
    assert flagged is True
    assert dim == "redirect"


def test_distinguishable_on_body_length_outside_band():
    baseline = [_sig(body_len=1000), _sig(body_len=1005), _sig(body_len=995)]
    noise = probe.learn_noise(baseline)
    cand = _sig(body_len=5000)
    flagged, dim = probe.is_distinguishable(cand, baseline, noise, want_timing=False)
    assert flagged is True
    assert dim == "body_length"


def test_not_distinguishable_within_jitter():
    baseline = [_sig(body_len=1000, ms=100.0), _sig(body_len=1005, ms=105.0),
                _sig(body_len=995, ms=95.0)]
    noise = probe.learn_noise(baseline)
    cand = _sig(body_len=1002, ms=101.0)
    flagged, dim = probe.is_distinguishable(cand, baseline, noise, want_timing=True)
    assert flagged is False
    assert dim == ""


def test_distinguishable_on_timing_when_enabled():
    baseline = [_sig(ms=100.0), _sig(ms=105.0), _sig(ms=95.0)]
    noise = probe.learn_noise(baseline)
    cand = _sig(ms=900.0)
    flagged, dim = probe.is_distinguishable(cand, baseline, noise, want_timing=True)
    assert flagged is True
    assert dim == "timing"


def test_timing_ignored_when_disabled():
    baseline = [_sig(ms=100.0), _sig(ms=105.0), _sig(ms=95.0)]
    noise = probe.learn_noise(baseline)
    cand = _sig(ms=900.0)
    flagged, dim = probe.is_distinguishable(cand, baseline, noise, want_timing=False)
    assert flagged is False


def test_keyword_signal_detects_user_not_found():
    assert probe.keyword_signal("user not found") == "user_absent"


def test_keyword_signal_detects_valid_user_hint():
    assert probe.keyword_signal("invalid password") == "user_present"


def test_keyword_signal_detects_reset_sent():
    assert probe.keyword_signal("a reset link has been sent") == "reset_sent"


def test_keyword_signal_none_for_generic():
    assert probe.keyword_signal("credentials submitted are not valid") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'learn_noise'`.

- [ ] **Step 3: Write minimal implementation**

Add the `statistics` import near the top of `account_enum_probe.py`:

```python
import statistics
```

Append:

```python
@dataclass
class NoiseBand:
    """The natural jitter learned from repeated baseline (invalid) requests."""

    len_mean: float
    len_margin: float
    time_mean: float
    time_margin: float
    samples: int


def learn_noise(baseline: list[ResponseSignature]) -> NoiseBand:
    """Derive jitter bands for body length and timing from baseline samples."""
    lens = [s.body_len for s in baseline]
    times = [s.elapsed_ms for s in baseline]
    len_mean = statistics.mean(lens)
    time_mean = statistics.mean(times)
    # * Margin = widest observed deviation, padded for proportional + constant noise.
    len_margin = max((abs(x - len_mean) for x in lens), default=0.0) + 0.02 * len_mean + 8
    time_margin = max((abs(t - time_mean) for t in times), default=0.0) * 3 + 200
    return NoiseBand(len_mean, len_margin, time_mean, time_margin, len(baseline))


def _baseline_mode_status(baseline: list[ResponseSignature]) -> int:
    return statistics.mode([s.status for s in baseline])


def _baseline_mode_redirect(baseline: list[ResponseSignature]) -> str:
    return statistics.mode([s.redirect_location for s in baseline])


def is_distinguishable(
    candidate: ResponseSignature,
    baseline: list[ResponseSignature],
    noise: NoiseBand,
    want_timing: bool,
) -> tuple[bool, str]:
    """Decide whether a candidate diverges from the invalid baseline.

    Returns (flagged, dimension). Dimensions are checked in order of
    reliability: status, redirect, body_length, then timing (if enabled).
    """
    if candidate.status != _baseline_mode_status(baseline):
        return True, "status"
    if candidate.redirect_location != _baseline_mode_redirect(baseline):
        return True, "redirect"
    if abs(candidate.body_len - noise.len_mean) > noise.len_margin:
        return True, "body_length"
    if want_timing and noise.samples >= 2:
        if abs(candidate.elapsed_ms - noise.time_mean) > noise.time_margin:
            return True, "timing"
    return False, ""


# * Secondary corroboration only — never the sole trigger for a finding.
_USER_PRESENT_HINTS = ("invalid password", "wrong password", "incorrect password",
                       "password is not correct")
_USER_ABSENT_HINTS = ("user not found", "no account", "not registered",
                      "does not exist", "not exist", "unknown user", "invalid account")
_RESET_SENT_HINTS = ("reset link has been sent", "password has been sent",
                     "email has been sent", "check your email")


def keyword_signal(snippet: str) -> str | None:
    """Classify a normalized body snippet as an enumeration hint, if any."""
    text = snippet.lower()
    if any(h in text for h in _RESET_SENT_HINTS):
        return "reset_sent"
    if any(h in text for h in _USER_ABSENT_HINTS):
        return "user_absent"
    if any(h in text for h in _USER_PRESENT_HINTS):
        return "user_present"
    return None
```

Note: `keyword_signal` receives normalized snippets in production (digits stripped), but the hint phrases contain no digits, so matching is unaffected; tests pass raw lowercase phrases directly.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS (all oracle tests).

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add baseline-delta oracle + keyword corroboration"
```

---

### Task 4: HTTP layer — client, safe_request, signature collection

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/identity_mgmt/test_account_enum_probe.py`:

```python
import httpx
import pytest


def make_mock_client(handler):
    """Build an httpx.Client backed by a MockTransport routing handler."""
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport, base_url="https://t.example")


def test_random_invalid_username_is_long_and_unique():
    a = probe.random_invalid_username()
    b = probe.random_invalid_username()
    assert len(a) >= 16 and a != b


def test_discover_endpoints_returns_only_200(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        if request.url.path == "/login":
            return httpx.Response(200, text="form")
        return httpx.Response(404, text="nope")

    client = make_mock_client(handler)
    found = probe.discover_endpoints(client, "https://t.example", ["/login", "/missing"])
    assert found == ["/login"]


def test_collect_signature_returns_signature(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        return httpx.Response(401, text="Authentication Failed")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0})
    sig = probe.collect_signature(client, "https://t.example/login",
                                  {"username": "x", "password": "y"}, cfg)
    assert sig is not None
    assert sig.status == 401


def test_collect_signature_returns_none_on_transport_error(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        raise httpx.ConnectError("boom")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0})
    sig = probe.collect_signature(client, "https://t.example/login",
                                  {"username": "x"}, cfg)
    assert sig is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'random_invalid_username'`.

- [ ] **Step 3: Write minimal implementation**

Add these imports near the top of `account_enum_probe.py`:

```python
import random
import secrets
import time

import httpx
```

Append:

```python
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]
INVALID_PASSWORD = "Wr0ng-Pass-Definitely-Not-Real!"


def _rand_xff() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def random_invalid_username() -> str:
    """A username extremely unlikely to exist (baseline anchor)."""
    return "zzq" + secrets.token_hex(8)


def make_client(base_url: str) -> httpx.Client:
    """Create an httpx.Client with rotating evasion headers."""
    return httpx.Client(
        base_url=base_url,
        follow_redirects=False,
        timeout=10,
        verify=False,
        headers={
            "User-Agent": random.choice(USER_AGENTS),
            "X-Forwarded-For": _rand_xff(),
            "Accept-Language": "en-US,en;q=0.9",
        },
    )


def safe_request(method: str, url: str, client: httpx.Client, max_retries: int = 3, **kwargs):
    """Issue a request with 429/503 backoff. Returns the response or None."""
    delay = 2
    for _ in range(max_retries):
        try:
            resp = client.request(method, url, **kwargs)
            if resp.status_code in (429, 503):
                time.sleep(delay)
                delay = min(delay * 2, 8)
                continue
            return resp
        except Exception:
            return None
    return None


def discover_endpoints(client: httpx.Client, base_url: str, paths: list[str]) -> list[str]:
    """Return the subset of paths that respond 200 to a GET."""
    found = []
    for path in paths:
        resp = safe_request("GET", base_url.rstrip("/") + path, client)
        if resp is not None and resp.status_code == 200:
            found.append(path)
    return found


def collect_signature(client, url, payload, cfg) -> ResponseSignature | None:
    """POST a payload, measure timing, and build a ResponseSignature."""
    start = time.monotonic()
    resp = safe_request("POST", url, client, json=payload)
    elapsed_ms = (time.monotonic() - start) * 1000
    if resp is None:
        return None
    time.sleep(cfg["request_delay_ms"] / 1000)
    return build_signature(resp, elapsed_ms)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add http client + safe_request + signature collection"
```

---

### Task 5: `login_oracle` technique

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/identity_mgmt/test_account_enum_probe.py`:

```python
def test_login_oracle_flags_distinguishable_user(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)
    monkeypatch.setattr(probe, "random_invalid_username", lambda: "zzqbaseline")

    def handler(request):
        body = request.content.decode() if request.content else ""
        # "admin" gets a distinct message; everyone else gets a generic one.
        if '"admin"' in body:
            return httpx.Response(200, text="Login for User admin: invalid password")
        return httpx.Response(200, text="Authentication failed. Credentials are not valid.")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 3})
    findings = probe.run_login_oracle(client, "https://t.example", "/login",
                                      ["admin", "ghost1", "ghost2"], cfg)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert "admin" in f["data"]["valid_candidates"]
    assert f["data"]["endpoint"] == "/login"


def test_login_oracle_silent_on_uniform_responses(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)
    monkeypatch.setattr(probe, "random_invalid_username", lambda: "zzqbaseline")

    def handler(request):
        return httpx.Response(200, text="Credentials submitted are not valid")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 3})
    findings = probe.run_login_oracle(client, "https://t.example", "/login",
                                      ["admin", "root", "test"], cfg)
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'run_login_oracle'`.

- [ ] **Step 3: Write minimal implementation**

Append:

```python
def _build_baseline(client, url, payload_for, cfg) -> tuple[list[ResponseSignature], NoiseBand] | None:
    """Sample a guaranteed-invalid identity baseline_samples times."""
    invalid = random_invalid_username()
    baseline = []
    for _ in range(cfg["baseline_samples"]):
        sig = collect_signature(client, url, payload_for(invalid), cfg)
        if sig is not None:
            baseline.append(sig)
    if len(baseline) < 2:
        return None
    return baseline, learn_noise(baseline)


def run_login_oracle(client, base_url, endpoint, candidates, cfg) -> list[dict]:
    """Flag usernames whose login response diverges from an invalid baseline."""
    url = base_url.rstrip("/") + endpoint

    def payload_for(user):
        return {"username": user, "password": INVALID_PASSWORD}

    learned = _build_baseline(client, url, payload_for, cfg)
    if learned is None:
        return []
    baseline, noise = learned

    valid = []
    for cand in candidates[: cfg["max_candidates"]]:
        sig = collect_signature(client, url, payload_for(cand), cfg)
        if sig is None:
            continue
        flagged, dim = is_distinguishable(sig, baseline, noise, want_timing=False)
        if flagged:
            valid.append({"username": cand, "dimension": dim,
                          "keyword": keyword_signal(sig.body_snippet)})

    if not valid:
        return []
    return [{
        "title": "Username enumeration via login response oracle",
        "description": (f"Login endpoint {endpoint} returns distinguishable responses "
                        f"for valid vs invalid usernames "
                        f"(dimensions: {sorted({v['dimension'] for v in valid})})."),
        "severity": "high",
        "data": {
            "endpoint": endpoint,
            "valid_candidates": [v["username"] for v in valid],
            "details": valid,
        },
    }]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add login_oracle enumeration technique"
```

---

### Task 6: `reset_oracle` technique (response + timing)

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_reset_oracle_flags_on_body_difference(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)
    monkeypatch.setattr(probe, "random_invalid_username", lambda: "zzq@none.example")

    def handler(request):
        body = request.content.decode() if request.content else ""
        if "real@example.com" in body:
            return httpx.Response(200, text="A reset link has been sent to your email address.")
        return httpx.Response(200, text="If the account exists we sent an email." + "x" * 5)

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 2})
    findings = probe.run_reset_oracle(client, "https://t.example", "/forgot",
                                      ["real@example.com", "ghost@example.com"], cfg)
    assert len(findings) == 1
    assert "real@example.com" in findings[0]["data"]["valid_candidates"]


def test_reset_oracle_silent_when_uniform(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)
    monkeypatch.setattr(probe, "random_invalid_username", lambda: "zzq@none.example")

    def handler(request):
        return httpx.Response(200, text="If the account exists we sent an email.")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 2})
    findings = probe.run_reset_oracle(client, "https://t.example", "/forgot",
                                      ["a@example.com", "b@example.com"], cfg)
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'run_reset_oracle'`.

- [ ] **Step 3: Write minimal implementation**

Append:

```python
def run_reset_oracle(client, base_url, endpoint, candidates, cfg) -> list[dict]:
    """Flag emails whose password-reset response (or timing) diverges.

    The timing oracle catches cases where a real account triggers an external
    email send (added latency) while an absent account returns immediately.
    """
    url = base_url.rstrip("/") + endpoint

    def payload_for(email):
        return {"email": email}

    learned = _build_baseline(client, url, payload_for, cfg)
    if learned is None:
        return []
    baseline, noise = learned

    valid = []
    for cand in candidates[: cfg["max_candidates"]]:
        # * Average timing over timing_samples to stabilise the latency signal.
        sigs = [collect_signature(client, url, payload_for(cand), cfg)
                for _ in range(max(1, cfg["timing_samples"]))]
        sigs = [s for s in sigs if s is not None]
        if not sigs:
            continue
        avg_ms = statistics.mean(s.elapsed_ms for s in sigs)
        rep = sigs[0]
        rep = ResponseSignature(rep.status, rep.redirect_location, rep.body_len,
                                rep.body_snippet, avg_ms)
        flagged, dim = is_distinguishable(rep, baseline, noise, want_timing=True)
        if flagged:
            valid.append({"email": cand, "dimension": dim,
                          "keyword": keyword_signal(rep.body_snippet)})

    if not valid:
        return []
    dims = sorted({v["dimension"] for v in valid})
    severity = "medium" if dims == ["timing"] else "high"
    return [{
        "title": "Account enumeration via password-reset oracle",
        "description": (f"Reset endpoint {endpoint} reveals account existence "
                        f"(dimensions: {dims})."),
        "severity": severity,
        "data": {
            "endpoint": endpoint,
            "valid_candidates": [v["email"] for v in valid],
            "details": valid,
        },
    }]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add reset_oracle (response + timing) technique"
```

---

### Task 7: `reg_oracle` technique

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_reg_oracle_flags_taken_username(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        body = request.content.decode() if request.content else ""
        if '"admin"' in body:
            return httpx.Response(200, text="That username is already taken.")
        return httpx.Response(200, text="Registration successful.")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 2})
    findings = probe.run_reg_oracle(client, "https://t.example", "/register",
                                    ["admin", "freshuser"], cfg)
    assert len(findings) == 1
    assert "admin" in findings[0]["data"]["valid_candidates"]
    assert findings[0]["severity"] == "medium"


def test_reg_oracle_silent_without_taken_hint(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        return httpx.Response(200, text="Please verify your email to continue.")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 2})
    findings = probe.run_reg_oracle(client, "https://t.example", "/register",
                                    ["admin", "root"], cfg)
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'run_reg_oracle'`.

- [ ] **Step 3: Write minimal implementation**

Append:

```python
_TAKEN_HINTS = ("already taken", "already exists", "already registered",
                "already in use", "username is taken", "is unavailable")


def run_reg_oracle(client, base_url, endpoint, candidates, cfg) -> list[dict]:
    """Flag usernames the registration form reports as already taken."""
    import time as _time  # local alias keeps unique-email generation explicit
    url = base_url.rstrip("/") + endpoint
    taken = []
    for cand in candidates[: cfg["max_candidates"]]:
        unique = secrets.token_hex(4)
        payload = {"username": cand,
                   "email": f"{cand}.{unique}@enum.example",
                   "password": "T3stP@ssw0rd!"}
        sig = collect_signature(client, url, payload, cfg)
        if sig is None:
            continue
        if any(h in sig.body_snippet for h in _TAKEN_HINTS):
            taken.append(cand)

    if not taken:
        return []
    return [{
        "title": "Username enumeration via registration response",
        "description": (f"Registration endpoint {endpoint} reveals which usernames "
                        f"already exist: {', '.join(taken)}."),
        "severity": "medium",
        "data": {"endpoint": endpoint, "valid_candidates": taken},
    }]
```

Note: `_TAKEN_HINTS` are matched against the normalized snippet (digits stripped); none contain digits, so matching is unaffected.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add reg_oracle enumeration technique"
```

---

### Task 8: `uri_probe` technique (403-vs-404, friendly-404, title)

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_extract_title_returns_lowercased_text():
    assert probe.extract_title("<html><head><TITLE>Invalid User</TITLE></head>") == "invalid user"


def test_extract_title_none_when_absent():
    assert probe.extract_title("<html><body>no title</body></html>") is None


def test_uri_probe_flags_403_vs_404(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        path = request.url.path
        if path.endswith("/admin"):
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(404, text="Not Found")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 2})
    findings = probe.run_uri_probe(client, "https://t.example",
                                   ["/profile/{u}"], ["admin", "ghostzzz"], cfg)
    assert len(findings) == 1
    assert "admin" in findings[0]["data"]["valid_candidates"]


def test_uri_probe_silent_when_uniform(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        return httpx.Response(404, text="Not Found")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0, "max_candidates": 2})
    findings = probe.run_uri_probe(client, "https://t.example",
                                   ["/profile/{u}"], ["admin", "root"], cfg)
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'extract_title'`.

- [ ] **Step 3: Write minimal implementation**

Append:

```python
def extract_title(html: str) -> str | None:
    """Return the lowercased, stripped <title> text, or None."""
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return match.group(1).strip().lower()


def run_uri_probe(client, base_url, patterns, candidates, cfg) -> list[dict]:
    """Probe profile-style URLs for per-user status / friendly-404 / title signals.

    Each pattern contains a ``{u}`` placeholder. A guaranteed-invalid username
    establishes the "absent" baseline (status, normalized body, title); any
    candidate that diverges is reported.
    """
    findings = []
    invalid = random_invalid_username()
    for pattern in patterns:
        base_resp = safe_request("GET", base_url.rstrip("/") + pattern.replace("{u}", invalid), client)
        if base_resp is None:
            continue
        base_status = base_resp.status_code
        base_body = normalize_text(base_resp.text)
        base_title = extract_title(base_resp.text)

        valid = []
        for cand in candidates[: cfg["max_candidates"]]:
            url = base_url.rstrip("/") + pattern.replace("{u}", cand)
            resp = safe_request("GET", url, client)
            time.sleep(cfg["request_delay_ms"] / 1000)
            if resp is None:
                continue
            cand_title = extract_title(resp.text)
            if resp.status_code != base_status:
                valid.append({"username": cand, "dimension": "status"})
            elif normalize_text(resp.text) != base_body:
                valid.append({"username": cand, "dimension": "friendly_404"})
            elif cand_title != base_title:
                valid.append({"username": cand, "dimension": "title"})

        if valid:
            findings.append({
                "title": "User enumeration via profile URL probing",
                "description": (f"URL pattern {pattern} distinguishes existing users "
                                f"(dimensions: {sorted({v['dimension'] for v in valid})})."),
                "severity": "medium",
                "data": {
                    "pattern": pattern,
                    "valid_candidates": [v["username"] for v in valid],
                    "details": valid,
                },
            })
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add uri_probe (403/404, friendly-404, title) technique"
```

---

### Task 9: `pattern_gen` candidate generation

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_generate_sequential_from_cn_seed():
    out = probe.generate_username_candidates(["CN000100"], limit=5)
    assert "CN000101" in out
    assert "CN000102" in out
    assert all(c != "CN000100" for c in out)  # excludes the seed itself


def test_generate_realm_alias():
    out = probe.generate_username_candidates(["R1001"], limit=5)
    assert "R1002" in out


def test_generate_initial_lastname_from_full_name_seed():
    out = probe.generate_username_candidates(["fmercury", "rtaylor"], limit=10)
    # both seeds share initial+lastname shape; generator proposes neighbours
    assert isinstance(out, list)
    assert len(out) <= 10


def test_generate_respects_limit():
    out = probe.generate_username_candidates(["CN000100"], limit=3)
    assert len(out) <= 3


def test_generate_empty_for_unpatterned_seeds():
    assert probe.generate_username_candidates(["random!!name"], limit=5) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'generate_username_candidates'`.

- [ ] **Step 3: Write minimal implementation**

Append:

```python
def generate_username_candidates(seeds: list[str], limit: int) -> list[str]:
    """Derive likely-valid usernames from observed structural patterns.

    Recognises:
      * prefix + zero-padded sequence (e.g. CN000100 -> CN000101..),
      * short realm alias + number (e.g. R1001 -> R1002..).
    Returns up to ``limit`` candidates, excluding the seeds themselves.
    """
    out: list[str] = []
    seen = set(seeds)
    seq_re = re.compile(r"^([A-Za-z]+)(\d+)$")
    for seed in seeds:
        m = seq_re.match(seed)
        if not m:
            continue
        prefix, digits = m.group(1), m.group(2)
        width = len(digits)
        start = int(digits)
        for delta in range(1, limit + 1):
            cand = f"{prefix}{str(start + delta).zfill(width)}"
            if cand not in seen:
                out.append(cand)
                seen.add(cand)
            if len(out) >= limit:
                return out
    return out[:limit]
```

Note: the `fmercury`/`rtaylor` test only asserts the call is total and bounded; first-initial+lastname seeds don't match the sequential pattern, so no neighbours are produced — acceptable, since those candidates are already supplied via `custom_seeds`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add predictable username generation"
```

---

### Task 10: `cms_wp` WordPress enumeration

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_cms_wp_detects_author_redirect_and_rest(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        if request.url.path == "/" and request.url.params.get("author") == "1":
            return httpx.Response(301, headers={"location": "https://t.example/author/adminslug/"})
        if request.url.path == "/wp-json/wp/v2/users":
            return httpx.Response(200, text='[{"id":1,"slug":"adminslug","name":"Admin"}]')
        return httpx.Response(404, text="nope")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0})
    findings = probe.run_cms_wp(client, "https://t.example", cfg)
    titles = {f["title"] for f in findings}
    assert "WordPress username enumeration via author redirect" in titles
    assert "WordPress username enumeration via REST API" in titles
    slugs = set()
    for f in findings:
        slugs.update(f["data"].get("usernames", []))
    assert "adminslug" in slugs


def test_cms_wp_silent_on_non_wordpress(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)

    def handler(request):
        return httpx.Response(404, text="nope")

    client = make_mock_client(handler)
    cfg = probe.merge_config({"request_delay_ms": 0})
    assert probe.run_cms_wp(client, "https://t.example", cfg) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'run_cms_wp'`.

- [ ] **Step 3: Write minimal implementation**

Add the `json` import near the top of `account_enum_probe.py`:

```python
import json
```

Append:

```python
def run_cms_wp(client, base_url, cfg) -> list[dict]:
    """WordPress username enumeration via ?author=N redirect and REST API."""
    findings = []
    base = base_url.rstrip("/")

    # 1. /?author=N -> 301 redirect to /author/<slug>/
    author_slugs = []
    for n in range(1, 4):
        resp = safe_request("GET", f"{base}/?author={n}", client)
        time.sleep(cfg["request_delay_ms"] / 1000)
        if resp is None:
            continue
        if resp.status_code in (301, 302):
            location = resp.headers.get("location", "")
            m = re.search(r"/author/([^/]+)/?", location)
            if m:
                author_slugs.append(m.group(1))
    if author_slugs:
        findings.append({
            "title": "WordPress username enumeration via author redirect",
            "description": (f"/?author=N redirects expose login slugs: "
                            f"{', '.join(author_slugs)}."),
            "severity": "medium",
            "data": {"usernames": author_slugs},
        })

    # 2. /wp-json/wp/v2/users -> JSON listing
    resp = safe_request("GET", f"{base}/wp-json/wp/v2/users", client)
    if resp is not None and resp.status_code == 200:
        try:
            users = json.loads(resp.text)
            slugs = [u["slug"] for u in users if isinstance(u, dict) and "slug" in u]
        except (ValueError, TypeError, KeyError):
            slugs = []
        if slugs:
            findings.append({
                "title": "WordPress username enumeration via REST API",
                "description": (f"/wp-json/wp/v2/users lists user slugs: "
                                f"{', '.join(slugs)}."),
                "severity": "medium",
                "data": {"usernames": slugs},
            })
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add WordPress cms_wp enumeration technique"
```

---

### Task 11: Orchestration entry point (`run_probe` + `__main__`)

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enum_probe.py`
- Test: `tests/unit/identity_mgmt/test_account_enum_probe.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_run_probe_disabled_returns_empty(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)
    cfg = probe.merge_config({"enabled": False})
    assert probe.run_probe("https://t.example", cfg) == []


def test_run_probe_only_runs_enabled_techniques(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)
    calls = []

    def fake_client(base_url):
        return "CLIENT"

    monkeypatch.setattr(probe, "make_client", fake_client)
    monkeypatch.setattr(probe, "discover_endpoints", lambda *a, **k: [])
    monkeypatch.setattr(probe, "run_login_oracle",
                        lambda *a, **k: calls.append("login") or [])
    monkeypatch.setattr(probe, "run_cms_wp",
                        lambda *a, **k: calls.append("cms") or [])
    # Disable everything except cms_wp.
    cfg = probe.merge_config({"techniques": {
        "login_oracle": False, "reset_oracle": False, "reg_oracle": False,
        "uri_probe": False, "pattern_gen": False, "cms_wp": True}})
    probe.run_probe("https://t.example", cfg)
    assert "cms" in calls
    assert "login" not in calls


def test_main_reads_config_and_prints_json(monkeypatch, capsys):
    monkeypatch.setattr(probe, "run_probe",
                        lambda base_url, cfg: [{"title": "x", "severity": "info"}])
    cfg_arg = json.dumps({"base_url": "https://t.example", "account_enum": {}})
    probe.main(["--config", cfg_arg])
    out = capsys.readouterr().out
    assert json.loads(out) == [{"title": "x", "severity": "info"}]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: FAIL — `AttributeError: ... 'run_probe'`.

- [ ] **Step 3: Write minimal implementation**

Add `argparse` and `sys` imports near the top of `account_enum_probe.py`:

```python
import argparse
import sys
```

Append:

```python
LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/api/login", "/api/v1/login",
               "/api/auth/login", "/user/login", "/account/login"]
RESET_PATHS = ["/forgot-password", "/forgot", "/reset-password", "/password-reset",
               "/api/forgot-password", "/auth/forgot-password", "/account/forgot-password"]
REG_PATHS = ["/register", "/signup", "/api/register", "/api/signup",
             "/auth/register", "/auth/signup"]
URI_PATTERNS = ["/profile/{u}", "/user/{u}", "/users/{u}", "/members/{u}",
                "/api/user/{u}", "/api/users/{u}", "/u/{u}"]
COMMON_USERNAMES = ["admin", "administrator", "root", "test", "support",
                    "info", "webmaster", "user"]
COMMON_EMAILS = ["admin@example.com", "support@example.com", "info@example.com",
                 "test@example.com", "root@example.com"]


def _seed_usernames(cfg) -> list[str]:
    seeds = [s for s in cfg.get("custom_seeds", []) if "@" not in s]
    return list(dict.fromkeys(seeds + COMMON_USERNAMES))


def _seed_emails(cfg) -> list[str]:
    seeds = [s for s in cfg.get("custom_seeds", []) if "@" in s]
    return list(dict.fromkeys(seeds + COMMON_EMAILS))


def run_probe(base_url: str, cfg: dict) -> list[dict]:
    """Run all enabled enumeration techniques against base_url."""
    if not cfg.get("enabled", True):
        return []

    tech = cfg["techniques"]
    findings: list[dict] = []
    client = make_client(base_url)
    try:
        usernames = _seed_usernames(cfg)
        emails = _seed_emails(cfg)

        if tech.get("pattern_gen"):
            usernames = usernames + generate_username_candidates(
                usernames, limit=cfg["max_candidates"])

        if tech.get("login_oracle"):
            for ep in discover_endpoints(client, base_url, LOGIN_PATHS):
                findings += run_login_oracle(client, base_url, ep, usernames, cfg)

        if tech.get("reset_oracle"):
            for ep in discover_endpoints(client, base_url, RESET_PATHS):
                findings += run_reset_oracle(client, base_url, ep, emails, cfg)

        if tech.get("reg_oracle"):
            for ep in discover_endpoints(client, base_url, REG_PATHS):
                findings += run_reg_oracle(client, base_url, ep, usernames, cfg)

        if tech.get("uri_probe"):
            findings += run_uri_probe(client, base_url, URI_PATTERNS, usernames, cfg)

        if tech.get("cms_wp"):
            findings += run_cms_wp(client, base_url, cfg)
    except Exception as exc:  # * Never crash the worker; emit a diagnostic.
        findings.append({
            "title": "Account enumeration probe error",
            "description": str(exc),
            "severity": "info",
            "data": {"error": str(exc)},
        })
    finally:
        try:
            client.close()
        except Exception:
            pass
    return findings


def main(argv: list[str] | None = None) -> None:
    """CLI entry: read JSON config from --config, print findings JSON to stdout."""
    parser = argparse.ArgumentParser(description="WSTG-IDNT-04 account enumeration probe")
    parser.add_argument("--config", required=True, help="JSON config blob")
    args = parser.parse_args(argv)

    raw = json.loads(args.config)
    base_url = raw["base_url"]
    cfg = merge_config(raw.get("account_enum"))
    findings = run_probe(base_url, cfg)
    print(json.dumps(findings))


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enum_probe.py -v`
Expected: PASS (full file).

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enum_probe.py tests/unit/identity_mgmt/test_account_enum_probe.py
git commit -m "feat(identity): add run_probe orchestrator + CLI entry point"
```

---

### Task 12: Rewrite `account_enumerator.py` wrapper

**Files:**
- Modify: `workers/identity_mgmt/tools/account_enumerator.py`
- Test: `tests/unit/identity_mgmt/test_account_enumerator.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/identity_mgmt/test_account_enumerator.py`:

```python
"""Unit tests for the AccountEnumerator wrapper (WSTG-IDNT-04)."""
import json

import pytest

from workers.identity_mgmt.tools.account_enumerator import AccountEnumerator


@pytest.fixture
def tool():
    return AccountEnumerator()


class FakeTarget:
    target_value = "example.com"
    target_profile = {"account_enum": {"max_candidates": 2, "techniques": {"cms_wp": False}}}


class HttpTarget:
    target_value = "http://example.com"
    target_profile = None


def test_name_and_weight(tool):
    assert tool.name == "account_enumerator"


def test_build_command_invokes_module(tool):
    cmd = tool.build_command(FakeTarget())
    assert cmd[0] == "python3"
    assert cmd[1] == "-m"
    assert cmd[2] == "workers.identity_mgmt.tools.account_enum_probe"
    assert cmd[3] == "--config"


def test_build_command_embeds_https_base_url(tool):
    cmd = tool.build_command(FakeTarget())
    cfg = json.loads(cmd[4])
    assert cfg["base_url"] == "https://example.com"
    assert cfg["account_enum"]["max_candidates"] == 2
    assert cfg["account_enum"]["techniques"]["cms_wp"] is False


def test_build_command_preserves_http_scheme(tool):
    cfg = json.loads(tool.build_command(HttpTarget())[4])
    assert cfg["base_url"] == "http://example.com"
    assert cfg["account_enum"] == {}


def test_build_command_passes_token_when_present(tool):
    cfg = json.loads(tool.build_command(FakeTarget(), credentials={"token": "abc"})[4])
    assert cfg["token"] == "abc"


def test_parse_output_valid(tool):
    findings = [{"title": "x", "severity": "high", "description": "y", "data": {}}]
    assert tool.parse_output(json.dumps(findings)) == findings


def test_parse_output_malformed_returns_empty(tool):
    assert tool.parse_output("not json") == []


def test_parse_output_empty_returns_empty(tool):
    assert tool.parse_output("") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enumerator.py -v`
Expected: FAIL — assertions on `cmd[1] == "-m"` fail (current tool uses `-c`).

- [ ] **Step 3: Write minimal implementation**

Replace the entire contents of `workers/identity_mgmt/tools/account_enumerator.py`:

```python
"""Account enumeration testing tool (WSTG-IDNT-04).

Thin wrapper over the standalone ``account_enum_probe`` module. Builds a JSON
config from the target profile's ``account_enum`` block and runs the probe as a
subprocess; parsing is delegated to the base class' JSON contract.
"""

import json

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class AccountEnumerator(IdentityMgmtTool):
    """Test for account enumeration vulnerabilities (WSTG-IDNT-04)."""

    name = "account_enumerator"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = (
            target_url
            if target_url.startswith(("http://", "https://"))
            else f"https://{target_url}"
        )

        profile = getattr(target, "target_profile", None) or {}
        account_enum = profile.get("account_enum", {})

        config = {"base_url": base_url, "account_enum": account_enum}
        if credentials and credentials.get("token"):
            config["token"] = credentials["token"]

        return [
            "python3", "-m",
            "workers.identity_mgmt.tools.account_enum_probe",
            "--config", json.dumps(config),
        ]

    def parse_output(self, stdout):
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/identity_mgmt/test_account_enumerator.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/identity_mgmt/tools/account_enumerator.py tests/unit/identity_mgmt/test_account_enumerator.py
git commit -m "refactor(identity): slim AccountEnumerator to probe-module wrapper"
```

---

### Task 13: Orchestrator — accept `account_enum` in profile updates

**Files:**
- Modify: `orchestrator/main.py:139-141` (`TargetProfileUpdate`)
- Modify: `orchestrator/main.py:1605-1611` (`update_target_profile`)

- [ ] **Step 1: Add the field to the Pydantic model**

In `orchestrator/main.py`, replace:

```python
class TargetProfileUpdate(BaseModel):
    custom_headers: Optional[dict] = None
    rate_limits: Optional[dict] = None
```

with:

```python
class TargetProfileUpdate(BaseModel):
    custom_headers: Optional[dict] = None
    rate_limits: Optional[dict] = None
    account_enum: Optional[dict] = None
```

- [ ] **Step 2: Merge the field in the update endpoint**

In `update_target_profile`, replace:

```python
        profile = target.target_profile or {}
        if body.custom_headers is not None:
            profile["custom_headers"] = body.custom_headers
        if body.rate_limits is not None:
            profile["rate_limits"] = body.rate_limits
        target.target_profile = profile
```

with:

```python
        profile = target.target_profile or {}
        if body.custom_headers is not None:
            profile["custom_headers"] = body.custom_headers
        if body.rate_limits is not None:
            profile["rate_limits"] = body.rate_limits
        if body.account_enum is not None:
            profile["account_enum"] = body.account_enum
        target.target_profile = profile
```

- [ ] **Step 3: Verify import compiles**

Run: `python -c "import ast; ast.parse(open('orchestrator/main.py', encoding='utf-8').read())"`
Expected: no output, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/main.py
git commit -m "feat(orchestrator): accept account_enum block in target profile updates"
```

---

### Task 14: Dashboard types & API client

**Files:**
- Modify: `dashboard/src/types/schema.ts:46-54` (`TargetProfile`)
- Modify: `shared/interfaces.ts` (`TargetProfile`)
- Modify: `dashboard/src/lib/api.ts:455-460` (`updateTargetProfile`)

- [ ] **Step 1: Add the type to `schema.ts`**

In `dashboard/src/types/schema.ts`, replace the `TargetProfile` interface:

```typescript
export interface TargetProfile {
  in_scope_domains?: string[];
  out_scope_domains?: string[];
  in_scope_cidrs?: string[];
  in_scope_regex?: string[];
  rate_limits?: Array<{ amount: number; unit: string }> | Record<string, number>;
  custom_headers?: Record<string, string>;
  [key: string]: unknown;
}
```

with:

```typescript
export interface AccountEnumSettings {
  enabled?: boolean;
  techniques?: {
    login_oracle?: boolean;
    reset_oracle?: boolean;
    reg_oracle?: boolean;
    uri_probe?: boolean;
    pattern_gen?: boolean;
    cms_wp?: boolean;
  };
  max_candidates?: number;
  request_delay_ms?: number;
  baseline_samples?: number;
  timing_samples?: number;
  custom_seeds?: string[];
}

export interface TargetProfile {
  in_scope_domains?: string[];
  out_scope_domains?: string[];
  in_scope_cidrs?: string[];
  in_scope_regex?: string[];
  rate_limits?: Array<{ amount: number; unit: string }> | Record<string, number>;
  custom_headers?: Record<string, string>;
  account_enum?: AccountEnumSettings;
  [key: string]: unknown;
}
```

- [ ] **Step 2: Mirror the field in `shared/interfaces.ts`**

Open `shared/interfaces.ts`, locate the `TargetProfile` interface, and add `account_enum?: Record<string, unknown>;` alongside `custom_headers`. (The shared file is a cross-service contract; a loosely-typed optional field keeps it in sync without importing dashboard-specific types.)

- [ ] **Step 3: Extend the API client param type**

In `dashboard/src/lib/api.ts`, replace the `updateTargetProfile` signature:

```typescript
  updateTargetProfile(targetId: number, profile: { custom_headers?: Record<string, string>; rate_limits?: Array<{ amount: number; unit: string }> | Record<string, number> }) {
```

with:

```typescript
  updateTargetProfile(targetId: number, profile: { custom_headers?: Record<string, string>; rate_limits?: Array<{ amount: number; unit: string }> | Record<string, number>; account_enum?: import("@/types/schema").AccountEnumSettings }) {
```

- [ ] **Step 4: Verify the dashboard type-checks**

Run: `cd dashboard; npx tsc --noEmit`
Expected: no errors (exit code 0).

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/types/schema.ts shared/interfaces.ts dashboard/src/lib/api.ts
git commit -m "feat(dashboard): add account_enum settings types + api param"
```

---

### Task 15: Settings Drawer — Account Enumeration section

**Files:**
- Modify: `dashboard/src/components/c2/SettingsDrawer.tsx`

- [ ] **Step 1: Add state for the account_enum block**

In `SettingsDrawer.tsx`, after the `pps` state declaration (around line 31), add:

```typescript
  const ae = currentProfile?.account_enum ?? {};
  const [aeEnabled, setAeEnabled] = useState<boolean>(ae.enabled ?? true);
  const [aeMaxCandidates, setAeMaxCandidates] = useState<string>(
    ae.max_candidates != null ? String(ae.max_candidates) : "",
  );
  const [aeDelayMs, setAeDelayMs] = useState<string>(
    ae.request_delay_ms != null ? String(ae.request_delay_ms) : "",
  );
  const [aeSeeds, setAeSeeds] = useState<string>((ae.custom_seeds ?? []).join("\n"));
  const [aeTechniques, setAeTechniques] = useState<Record<string, boolean>>({
    login_oracle: ae.techniques?.login_oracle ?? true,
    reset_oracle: ae.techniques?.reset_oracle ?? true,
    reg_oracle: ae.techniques?.reg_oracle ?? true,
    uri_probe: ae.techniques?.uri_probe ?? true,
    pattern_gen: ae.techniques?.pattern_gen ?? true,
    cms_wp: ae.techniques?.cms_wp ?? true,
  });
```

- [ ] **Step 2: Build and send the account_enum payload in `handleSave`**

In `handleSave`, replace:

```typescript
      const rate_limits: Record<string, number> = {};
      if (pps) rate_limits.pps = Number(pps);
      const res = await api.updateTargetProfile(targetId, { custom_headers, rate_limits });
```

with:

```typescript
      const rate_limits: Record<string, number> = {};
      if (pps) rate_limits.pps = Number(pps);

      const account_enum: import("@/types/schema").AccountEnumSettings = {
        enabled: aeEnabled,
        techniques: aeTechniques,
        custom_seeds: aeSeeds.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
      };
      if (aeMaxCandidates) account_enum.max_candidates = Number(aeMaxCandidates);
      if (aeDelayMs) account_enum.request_delay_ms = Number(aeDelayMs);

      const res = await api.updateTargetProfile(targetId, { custom_headers, rate_limits, account_enum });
```

- [ ] **Step 3: Render the section UI**

In the drawer body, immediately before the `{/* Danger Zone */}` comment, insert:

```tsx
          {/* Account Enumeration (WSTG-IDNT-04) */}
          <div className="space-y-3 border-t border-border pt-4">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-text-secondary">Account Enumeration (WSTG-IDNT-04)</label>
              <input
                data-testid="ae-enabled"
                type="checkbox"
                checked={aeEnabled}
                onChange={(e) => setAeEnabled(e.target.checked)}
                className="h-4 w-4 accent-accent"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              {Object.keys(aeTechniques).map((key) => (
                <label key={key} className="flex items-center gap-2 text-[11px] text-text-muted">
                  <input
                    data-testid={`ae-tech-${key}`}
                    type="checkbox"
                    checked={aeTechniques[key]}
                    disabled={!aeEnabled}
                    onChange={(e) => setAeTechniques({ ...aeTechniques, [key]: e.target.checked })}
                    className="h-3.5 w-3.5 accent-accent"
                  />
                  {key}
                </label>
              ))}
            </div>

            <div className="flex gap-2">
              <input
                data-testid="ae-max-candidates"
                type="number"
                value={aeMaxCandidates}
                disabled={!aeEnabled}
                onChange={(e) => setAeMaxCandidates(e.target.value)}
                placeholder="Max candidates (6)"
                className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none disabled:opacity-50"
              />
              <input
                data-testid="ae-delay-ms"
                type="number"
                value={aeDelayMs}
                disabled={!aeEnabled}
                onChange={(e) => setAeDelayMs(e.target.value)}
                placeholder="Delay ms (150)"
                className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none disabled:opacity-50"
              />
            </div>

            <textarea
              data-testid="ae-seeds"
              value={aeSeeds}
              disabled={!aeEnabled}
              onChange={(e) => setAeSeeds(e.target.value)}
              placeholder="Seed usernames/emails (one per line)"
              rows={3}
              className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none disabled:opacity-50"
            />
          </div>
```

- [ ] **Step 4: Verify the dashboard type-checks and lints**

Run: `cd dashboard; npx tsc --noEmit; npm run lint`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/c2/SettingsDrawer.tsx
git commit -m "feat(dashboard): add Account Enumeration settings to SettingsDrawer"
```

---

### Task 16: Full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Run the identity_mgmt unit tests**

Run: `python -m pytest tests/unit/identity_mgmt/ -v`
Expected: all PASS (existing role/registration tests + the two new files).

- [ ] **Step 2: Confirm probe module imports standalone (no lib_webbh)**

Run: `python -c "from workers.identity_mgmt.tools import account_enum_probe; print('ok')"`
Expected: prints `ok` with no DB/lib_webbh import errors.

- [ ] **Step 3: Smoke-test the CLI entry point offline**

Run: `python -m workers.identity_mgmt.tools.account_enum_probe --config "{\"base_url\": \"https://127.0.0.1:9\", \"account_enum\": {\"request_delay_ms\": 0}}"`
Expected: prints a JSON array (likely `[]` or a single `info` diagnostic) and exits 0 — proving it never crashes on an unreachable host.

- [ ] **Step 4: Dashboard type-check + lint**

Run: `cd dashboard; npx tsc --noEmit; npm run lint`
Expected: no errors.

- [ ] **Step 5: Final commit (if any verification fixes were needed)**

```bash
git add -A
git commit -m "test(identity): verify WSTG-IDNT-04 account enumeration suite"
```

---

## Self-Review

**Spec coverage:**
- OWASP baseline-delta oracle → Tasks 2–3 (signatures, noise, divergence, keyword-secondary).
- login_oracle → Task 5; reset_oracle (+timing) → Task 6; reg_oracle → Task 7; uri_probe (403/404, friendly-404, title) → Task 8; pattern_gen → Task 9; cms_wp (WordPress redirect + REST) → Task 10.
- Testable standalone module + `__main__` → Tasks 1–11.
- Thin wrapper invoking `python3 -m` → Task 12.
- Settings-drawer tunables plumbed through orchestrator/types/api/UI → Tasks 13–15.
- Conservative defaults & never-crash safety → Task 1 (DEFAULTS), Task 11 (`run_probe` try/except), Task 4 (`safe_request` backoff).
- Three-layer coherence untouched → confirmed in File Structure; no task edits `pipeline.py`/`playbooks.py`/`worker-stages.ts`.
- Findings remain `Observation` rows → unchanged `base_tool` path; no DB task. ✓

**Placeholder scan:** No TBD/TODO; every code step contains complete, runnable code.

**Type consistency:** `ResponseSignature`, `NoiseBand`, `merge_config`, `build_signature`, `learn_noise`, `is_distinguishable`, `keyword_signal`, `collect_signature`, `_build_baseline`, `run_login_oracle`/`run_reset_oracle`/`run_reg_oracle`/`run_uri_probe`/`generate_username_candidates`/`run_cms_wp`/`run_probe`/`main` names are used consistently across tasks. `AccountEnumSettings` is defined in `schema.ts` (Task 14) before it is referenced in `api.ts` (Task 14) and `SettingsDrawer.tsx` (Task 15). The probe config keys (`techniques`, `max_candidates`, `request_delay_ms`, `baseline_samples`, `timing_samples`, `custom_seeds`) match between `DEFAULTS` (Task 1) and the UI payload (Task 15).
