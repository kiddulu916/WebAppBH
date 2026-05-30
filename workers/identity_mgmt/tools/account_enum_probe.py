"""Account enumeration probe (WSTG-IDNT-04).

Standalone, dependency-light module (httpx + stdlib only; no lib_webbh/DB
imports) so it can be unit-tested in isolation and invoked as a subprocess by
``account_enumerator.py`` via ``python3 -m``.

Implements the OWASP baseline-delta oracle: per endpoint, learn the natural
response jitter from a guaranteed-invalid username, then flag a candidate as a
likely valid account only when its response diverges beyond that jitter band.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import re
import secrets
import statistics
import sys
import time
from dataclasses import dataclass

import httpx

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


# ---------------------------------------------------------------------------
# Response signatures & normalization
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# The oracle: noise learning, divergence decision, keyword corroboration
# ---------------------------------------------------------------------------
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
    # * Compare body text only when the baseline is uniform; a varying baseline
    # * means volatile page content (tokens, counters) we cannot trust.
    baseline_snippets = {s.body_snippet for s in baseline}
    if len(baseline_snippets) == 1 and candidate.body_snippet not in baseline_snippets:
        return True, "body_text"
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


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Techniques
# ---------------------------------------------------------------------------
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


_TAKEN_HINTS = ("already taken", "already exists", "already registered",
                "already in use", "username is taken", "is unavailable")


def run_reg_oracle(client, base_url, endpoint, candidates, cfg) -> list[dict]:
    """Flag usernames the registration form reports as already taken."""
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


# ---------------------------------------------------------------------------
# Orchestration & CLI entry point
# ---------------------------------------------------------------------------
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
