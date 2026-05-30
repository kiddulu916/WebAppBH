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
    assert cfg["baseline_samples"] == 3


def test_merge_config_merges_techniques_partially():
    cfg = probe.merge_config({"techniques": {"cms_wp": False}})
    assert cfg["techniques"]["cms_wp"] is False
    assert cfg["techniques"]["login_oracle"] is True


def test_merge_config_does_not_mutate_defaults():
    probe.merge_config({"max_candidates": 99, "techniques": {"login_oracle": False}})
    assert probe.DEFAULTS["max_candidates"] == 6
    assert probe.DEFAULTS["techniques"]["login_oracle"] is True


# ── signatures & normalization ──────────────────────────────────────────────

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


# ── oracle ──────────────────────────────────────────────────────────────────

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


# ── HTTP layer ──────────────────────────────────────────────────────────────

import httpx  # noqa: E402
import pytest  # noqa: E402


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


# ── login_oracle ────────────────────────────────────────────────────────────

def test_login_oracle_flags_distinguishable_user(monkeypatch):
    monkeypatch.setattr(probe.time, "sleep", lambda *_: None)
    monkeypatch.setattr(probe, "random_invalid_username", lambda: "zzqbaseline")

    def handler(request):
        body = request.content.decode() if request.content else ""
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


# ── reset_oracle ────────────────────────────────────────────────────────────

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


# ── reg_oracle ──────────────────────────────────────────────────────────────

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


# ── uri_probe ───────────────────────────────────────────────────────────────

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


# ── pattern_gen ─────────────────────────────────────────────────────────────

def test_generate_sequential_from_cn_seed():
    out = probe.generate_username_candidates(["CN000100"], limit=5)
    assert "CN000101" in out
    assert "CN000102" in out
    assert all(c != "CN000100" for c in out)


def test_generate_realm_alias():
    out = probe.generate_username_candidates(["R1001"], limit=5)
    assert "R1002" in out


def test_generate_initial_lastname_from_full_name_seed():
    out = probe.generate_username_candidates(["fmercury", "rtaylor"], limit=10)
    assert isinstance(out, list)
    assert len(out) <= 10


def test_generate_respects_limit():
    out = probe.generate_username_candidates(["CN000100"], limit=3)
    assert len(out) <= 3


def test_generate_empty_for_unpatterned_seeds():
    assert probe.generate_username_candidates(["random!!name"], limit=5) == []


# ── cms_wp ──────────────────────────────────────────────────────────────────

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


# ── run_probe / main ────────────────────────────────────────────────────────

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
