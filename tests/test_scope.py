from lib_webbh.scope import ScopeManager, ScopeResult


def _make_profile(in_scope_domains=None, out_scope_domains=None, in_scope_cidrs=None, in_scope_regex=None):
    return {
        "in_scope_domains": in_scope_domains or [],
        "out_scope_domains": out_scope_domains or [],
        "in_scope_cidrs": in_scope_cidrs or [],
        "in_scope_regex": in_scope_regex or [],
    }


# --- Domain matching ---

def test_wildcard_domain_matches_subdomain():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("api.example.com")
    assert result.in_scope is True
    assert result.normalized == "api.example.com"
    assert result.asset_type == "domain"


def test_wildcard_domain_matches_deep_subdomain():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("deep.sub.api.example.com")
    assert result.in_scope is True
    assert result.normalized == "deep.sub.api.example.com"


def test_exact_domain_no_match():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("other.com")
    assert result.in_scope is False


def test_out_of_scope_overrides_in_scope():
    sm = ScopeManager(_make_profile(
        in_scope_domains=["*.example.com"],
        out_scope_domains=["admin.example.com"],
    ))
    result = sm.is_in_scope("admin.example.com")
    assert result.in_scope is False


# --- URL normalization ---

def test_url_strips_scheme_and_extracts_path():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("https://api.example.com/v1/users?id=1")
    assert result.in_scope is True
    assert result.normalized == "api.example.com"
    assert result.path == "/v1/users?id=1"
    assert result.asset_type == "domain"


def test_url_http_scheme_stripped():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("http://app.example.com/login")
    assert result.normalized == "app.example.com"
    assert result.path == "/login"


# --- CIDR/IP matching ---

def test_ip_in_cidr_scope():
    sm = ScopeManager(_make_profile(in_scope_cidrs=["192.168.1.0/24"]))
    result = sm.is_in_scope("192.168.1.50")
    assert result.in_scope is True
    assert result.asset_type == "ip"
    assert result.normalized == "192.168.1.50"


def test_ip_outside_cidr_scope():
    sm = ScopeManager(_make_profile(in_scope_cidrs=["192.168.1.0/24"]))
    result = sm.is_in_scope("10.0.0.1")
    assert result.in_scope is False


def test_cidr_input_matched():
    sm = ScopeManager(_make_profile(in_scope_cidrs=["10.0.0.0/8"]))
    result = sm.is_in_scope("10.0.0.0/24")
    assert result.in_scope is True
    assert result.asset_type == "cidr"


# --- Regex matching ---

def test_regex_scope_match():
    sm = ScopeManager(_make_profile(in_scope_regex=[r".*\.internal\.corp$"]))
    result = sm.is_in_scope("secret.internal.corp")
    assert result.in_scope is True


def test_regex_scope_no_match():
    sm = ScopeManager(_make_profile(in_scope_regex=[r".*\.internal\.corp$"]))
    result = sm.is_in_scope("public.external.com")
    assert result.in_scope is False


# --- Dynamic rules ---

def test_add_rule_at_runtime():
    sm = ScopeManager(_make_profile())
    sm.add_rule("*.newdomain.io", in_scope=True)
    result = sm.is_in_scope("app.newdomain.io")
    assert result.in_scope is True


# --- Summary ---

def test_get_scope_summary():
    sm = ScopeManager(_make_profile(
        in_scope_domains=["*.example.com"],
        in_scope_cidrs=["10.0.0.0/8"],
        in_scope_regex=[r".*\.corp$"],
    ))
    summary = sm.get_scope_summary()
    assert "domains" in summary
    assert "networks" in summary
    assert "regex" in summary
