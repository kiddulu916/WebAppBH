"""Find Engagement — two-phase platform lookup and policy parser.

Phase 1 (search_programs): company name -> list[ProgramCandidate]
Phase 2 (fetch_engagement): program URL/handle -> EngagementResult -> CampaignFormPrefill
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

from lib_webbh.platform_api.base import ScopeEntry

DEFAULT_TIMEOUT = 20.0
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ProgramCandidate:
    name: str
    handle: str
    url: str
    platform: str


@dataclass
class StageRule:
    stage_name: str
    out_of_scope: bool
    chain_exception: bool
    reason: str


@dataclass
class EngagementResult:
    platform: str
    handle: str
    program_name: str
    in_scope: list[ScopeEntry]
    out_of_scope_entries: list[ScopeEntry]
    rate_limit: int | None
    custom_headers: dict[str, str]
    guidelines: str
    stage_rules: list[StageRule]
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class CampaignFormPrefill:
    program_name: str
    seed_targets: list[str]
    in_scope: list[str]
    out_of_scope: list[str]
    rate_limit: int | None
    custom_headers: dict[str, str]
    guidelines: str
    conditional_stages: dict[str, dict]
    parse_warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Attack keyword map — stage_name -> keywords to match in policy text
# ---------------------------------------------------------------------------
ATTACK_KEYWORD_MAP: dict[str, list[str]] = {
    # info_gathering
    "search_engine_recon":          ["search engine", "google dork", "shodan"],
    "web_server_fingerprint":       ["fingerprint", "banner grab"],
    "web_server_metafiles":         ["robots.txt", "sitemap", "metafile"],
    "enumerate_applications":       ["enumerate application", "port scan", "application enumeration"],
    "review_comments":              ["source code review", "html comment"],
    "identify_entry_points":        ["entry point", "endpoint enumeration"],
    "aggregate_entry_points":       [],
    "map_execution_paths":          ["path mapping", "execution path"],
    "review_comments_deep":         [],
    "fingerprint_framework":        ["framework fingerprint"],
    "map_architecture":             ["architecture mapping"],
    "map_application":              ["application mapping"],
    # config_mgmt
    "network_config":               ["network configuration"],
    "network_config_cred_test":     ["default credential", "default password"],
    "platform_config":              ["platform configuration"],
    "file_extension_handling":      ["file extension"],
    "backup_files":                 ["backup file", ".bak", ".old"],
    "admin_interface_enumeration":  ["admin interface", "admin panel"],
    "api_discovery":                ["api discovery", "api enumeration"],
    "http_methods":                 ["http method", "verb tampering", "options method"],
    "hsts_testing":                 ["hsts", "strict transport"],
    "rpc_testing":                  ["rpc", "xml-rpc"],
    "file_permission":              ["file permission"],
    "file_inclusion":               ["file inclusion", "lfi", "local file inclusion", "rfi", "remote file inclusion"],
    "subdomain_takeover":           ["subdomain takeover", "dangling dns"],
    "cloud_storage":                ["s3 bucket", "cloud storage", "blob storage"],
    "csp_testing":                  ["content security policy", "csp"],
    "path_confusion":               ["path confusion", "path traversal"],
    "security_headers":             ["security header", "missing header"],
    # identity_mgmt
    "role_definitions":             ["role definition", "rbac"],
    "registration_process":         ["registration", "account creation", "sign up"],
    "account_provisioning":         ["account provisioning", "account creation"],
    "account_enumeration":          ["account enumeration", "user enumeration", "username enumeration"],
    "weak_username_policy":         ["username policy", "weak username"],
    # authentication
    "credentials_transport":        ["credential transport", "password in plaintext", "http login"],
    "default_credentials":          ["default credential", "default password", "default login"],
    "lockout_mechanism":            ["brute force", "credential stuffing", "account lockout", "brute-force"],
    "auth_bypass":                  ["authentication bypass", "auth bypass"],
    "remember_password":            ["remember password", "remember me"],
    "browser_cache":                ["browser cache", "cached credential"],
    "weak_password_policy":         ["weak password", "password policy", "password complexity"],
    "security_questions":           ["security question"],
    "password_change":              ["password change", "password reset"],
    "multi_channel_auth":           ["multi-factor", "mfa", "2fa", "otp"],
    # authorization
    "directory_traversal":          ["directory traversal", "path traversal", "../"],
    "authz_bypass":                 ["authorization bypass", "access control bypass"],
    "privilege_escalation":         ["privilege escalation", "vertical privilege"],
    "idor":                         ["idor", "insecure direct object", "bola"],
    # session_mgmt
    "session_scheme":               ["session token", "session management"],
    "cookie_attributes":            ["cookie attribute", "httponly", "secure flag", "samesite"],
    "session_fixation":             ["session fixation"],
    "exposed_variables":            ["exposed variable", "session variable"],
    "csrf":                         ["csrf", "cross-site request forgery"],
    "logout_functionality":         ["logout", "session termination"],
    "session_timeout":              ["session timeout", "session expiry"],
    "session_puzzling":             ["session puzzling", "session variable overloading"],
    "session_hijacking":            ["session hijacking", "session theft"],
    # input_validation
    "reflected_xss":                ["reflected xss", "non-persistent xss"],
    "stored_xss":                   ["stored xss", "persistent xss", "stored cross-site"],
    "http_verb_tampering":          ["verb tampering", "http verb"],
    "http_param_pollution":         ["parameter pollution", "hpp"],
    "sql_injection":                ["sql injection", "sqli"],
    "ldap_injection":               ["ldap injection"],
    "xml_injection":                ["xml injection", "xxe", "xml external entity"],
    "ssti":                         ["ssti", "server-side template injection", "template injection"],
    "xpath_injection":              ["xpath injection"],
    "imap_smtp_injection":          ["imap injection", "smtp injection", "email injection"],
    "code_injection":               ["code injection", "code execution", "rce", "remote code execution"],
    "command_injection":            ["command injection", "os injection", "shell injection"],
    "format_string":                ["format string"],
    "host_header_injection":        ["host header injection", "host header attack"],
    "ssrf":                         ["ssrf", "server-side request forgery"],
    "buffer_overflow":              ["buffer overflow"],
    "http_smuggling":               ["http smuggling", "request smuggling", "http desync"],
    "websocket_injection":          ["websocket injection", "websocket"],
    # error_handling
    "error_codes":                  ["error code", "error message", "verbose error"],
    "stack_traces":                 ["stack trace", "exception detail"],
    # cryptography
    "tls_testing":                  ["tls", "ssl", "weak cipher", "certificate"],
    "padding_oracle":               ["padding oracle", "cbc padding"],
    "plaintext_transmission":       ["plaintext", "unencrypted transmission"],
    "weak_crypto":                  ["weak cryptography", "md5", "sha1", "weak hash"],
    # business_logic
    "data_validation":              ["data validation", "input validation"],
    "request_forgery":              ["request forgery"],
    "integrity_checks":             ["integrity check", "tamper"],
    "process_timing":               ["race condition", "time-of-check", "toctou"],
    "rate_limiting":                ["rate limit", "rate-limit", "automated scanning", "automated tool"],
    "workflow_bypass":              ["workflow bypass", "business logic bypass"],
    "application_misuse":           ["application misuse", "abuse"],
    "file_upload_validation":       ["file upload", "unrestricted upload"],
    "malicious_file_upload":        ["malicious file", "malicious upload", "webshell"],
    # client_side
    "dom_xss":                      ["dom xss", "dom-based xss"],
    "clickjacking":                 ["clickjacking", "click-jacking", "ui redressing"],
    "csrf_tokens":                  ["csrf token", "anti-csrf"],
    "csp_bypass":                   ["csp bypass", "content security policy bypass"],
    "html5_injection":              ["html5 injection", "html injection"],
    "web_storage":                  ["localstorage", "sessionstorage", "web storage"],
    "client_side_logic":            ["client-side logic", "javascript logic"],
    "dom_based_injection":          ["dom injection", "dom manipulation"],
    "client_side_resource_manipulation": ["resource manipulation", "client-side resource"],
    "client_side_auth":             ["client-side authentication", "client-side auth"],
    "xss_client_side":              ["cross-site scripting"],
    "css_injection":                ["css injection"],
    "malicious_upload_client":      ["malicious upload client"],
    # mobile_worker
    "acquire_decompile":            ["decompile", "apk", "ipa", "binary analysis"],
    "secret_extraction":            ["secret extraction", "hardcoded secret", "mobile secret"],
    "configuration_audit":          ["mobile configuration", "app configuration"],
    "dynamic_analysis":             ["dynamic analysis", "frida", "runtime analysis"],
    "endpoint_feedback":            ["mobile endpoint", "api endpoint feedback"],
    # reasoning_worker
    "finding_correlation":          ["finding correlation", "vulnerability correlation"],
    "impact_analysis":              ["impact analysis", "severity analysis"],
    "chain_hypothesis":             ["chain hypothesis", "attack chain"],
    # chain_worker
    "data_collection":              ["data collection", "chain data"],
    "chain_evaluation":             ["chain evaluation", "exploit chain"],
    "ai_chain_discovery":           ["ai chain", "automated chain discovery"],
    "chain_execution":              ["chain execution", "exploit execution"],
    "reporting":                    ["reporting", "report generation"],
    # reporting_worker
    "data_gathering":               ["data gathering", "finding aggregation"],
    "deduplication":                ["deduplication", "duplicate finding"],
    "rendering":                    ["report rendering", "html report"],
    "export":                       ["report export", "pdf export"],
}

# Regex: detect exception clause — MUST be applied to the sentence/paragraph containing
# the OOS keyword, not the full policy text (to avoid false positives from unrelated mentions).
_EXCEPTION_RE = re.compile(
    r"unless\s.{0,80}(critical|deeper|higher|greater|harder|significant|severe)\s*impact",
    re.IGNORECASE,
)

# Regex: parse rate limit from policy text
_RATE_LIMIT_RE = re.compile(
    r"(\d+)\s*(?:req(?:uest)?s?)\s*(?:/|\s*per\s*)\s*(s(?:ec(?:ond)?)?|min(?:ute)?)",
    re.IGNORECASE,
)

# Regex: find custom X- headers required by the platform
_CUSTOM_HEADER_RE = re.compile(r"(X-[A-Za-z0-9\-]+)\s*:\s*([^\n\r,]+)", re.MULTILINE)

# ---------------------------------------------------------------------------
# Phase 1 — Search functions
# ---------------------------------------------------------------------------

async def _search_hackerone(
    client: httpx.AsyncClient,
    company_name: str,
    credentials: dict,
) -> list[ProgramCandidate]:
    token = credentials.get("token", "")
    username = credentials.get("username", "")
    resp = await client.get(
        "https://api.hackerone.com/v1/hackers/programs",
        params={"query": company_name, "sort": "name:ascending", "page[size]": 10},
        auth=(username, token),
    )
    resp.raise_for_status()
    data = resp.json()
    candidates = []
    for prog in data.get("data", []):
        attrs = prog.get("attributes", {})
        handle = attrs.get("handle", "")
        if not handle:
            continue
        candidates.append(ProgramCandidate(
            name=attrs.get("name", handle),
            handle=handle,
            url=f"https://hackerone.com/{handle}",
            platform="hackerone",
        ))
    return candidates


async def _search_bugcrowd(
    client: httpx.AsyncClient,
    company_name: str,
) -> list[ProgramCandidate]:
    resp = await client.get(
        "https://bugcrowd.com/programs",
        params={"q": company_name},
        headers=_BROWSER_HEADERS,
    )
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find(attrs={"data-react-class": "ResearcherProgramCards"})
    if not tag:
        return []
    try:
        props = json.loads(tag["data-react-props"])
        programs = props.get("programs", [])
    except (KeyError, json.JSONDecodeError):
        return []
    return [
        ProgramCandidate(
            name=p.get("name", p.get("program_id", "")),
            handle=p.get("program_id", ""),
            url=f"https://bugcrowd.com{p.get('program_url', '')}",
            platform="bugcrowd",
        )
        for p in programs
        if p.get("program_type") == "bug_bounty" and p.get("program_id")
    ]


async def _search_intigriti(
    client: httpx.AsyncClient,
    company_name: str,
) -> list[ProgramCandidate]:
    resp = await client.get(
        "https://app.intigriti.com/programs",
        params={"search": company_name},
        headers=_BROWSER_HEADERS,
    )
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__INTIGRITI_DATA__"})
    if not tag:
        return []
    raw = tag.string
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
        programs = data.get("programs", [])
    except json.JSONDecodeError:
        return []
    return [
        ProgramCandidate(
            name=p.get("name", ""),
            handle=p.get("programHandle", ""),
            url=p.get("url", ""),
            platform="intigriti",
        )
        for p in programs
        if p.get("programHandle") and p.get("name")
    ]


async def _search_yeswehack(
    client: httpx.AsyncClient,
    company_name: str,
) -> list[ProgramCandidate]:
    resp = await client.get(
        "https://yeswehack.com/programs",
        params={"text": company_name},
        headers=_BROWSER_HEADERS,
    )
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__NUXT_DATA__"})
    if not tag:
        return []
    raw = tag.string
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
        items = data.get("programs", {}).get("items", [])
    except json.JSONDecodeError:
        return []
    return [
        ProgramCandidate(
            name=p.get("title", p.get("slug", "")),
            handle=p.get("slug", ""),
            url=p.get("url", f"https://yeswehack.com/programs/{p.get('slug', '')}"),
            platform="yeswehack",
        )
        for p in items
        if p.get("slug")
    ]


# ---------------------------------------------------------------------------
# Phase 2 — Fetch functions (return normalised raw dict)
# ---------------------------------------------------------------------------

_RAW_KEYS = ("program_name", "in_scope_raw", "out_of_scope_raw", "guidelines")


async def _fetch_hackerone(
    client: httpx.AsyncClient,
    handle: str,
    credentials: dict,
) -> dict:
    token = credentials.get("token", "")
    username = credentials.get("username", "")
    resp = await client.get(
        f"https://api.hackerone.com/v1/programs/{handle}",
        auth=(username, token),
    )
    resp.raise_for_status()
    data = resp.json()
    attrs = data.get("data", {}).get("attributes", {})
    scopes_data = (
        data.get("data", {})
        .get("relationships", {})
        .get("structured_scopes", {})
        .get("data", [])
    )
    in_scope_raw, out_of_scope_raw = [], []
    for s in scopes_data:
        sa = s.get("attributes", {})
        entry = {
            "asset_type": sa.get("asset_type", "unknown").lower(),
            "asset_value": sa.get("asset_identifier", ""),
            "eligible_for_bounty": sa.get("eligible_for_bounty", False),
            "in_scope": not sa.get("out_of_scope", False),
        }
        if entry["in_scope"]:
            in_scope_raw.append(entry)
        else:
            out_of_scope_raw.append(entry)
    return {
        "program_name": attrs.get("name", handle),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": attrs.get("policy", ""),
    }


async def _fetch_bugcrowd(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url, headers=_BROWSER_HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find(attrs={"data-react-class": "ProgramBrief"})
    warnings: list[str] = []
    if not tag:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Bugcrowd: could not find program data block"]}
    try:
        props = json.loads(tag["data-react-props"])
        prog = props.get("program", {})
    except (KeyError, json.JSONDecodeError):
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Bugcrowd: failed to parse program data"]}

    in_scope_raw, out_of_scope_raw = [], []
    for group in prog.get("target_groups", []):
        for t in group.get("targets", []):
            entry = {
                "asset_type": t.get("category", "website").lower(),
                "asset_value": t.get("name", ""),
                "eligible_for_bounty": t.get("eligible_for_bounty", t.get("bounty", t.get("in_scope", False))),
            }
            if t.get("in_scope", True):
                in_scope_raw.append(entry)
            else:
                out_of_scope_raw.append(entry)

    return {
        "program_name": prog.get("name", ""),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": prog.get("briefing_text", ""),
        "_warnings": warnings,
    }


async def _fetch_intigriti(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url, headers=_BROWSER_HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__INTIGRITI_SCOPE__"})
    if not tag:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Intigriti: could not find scope data block"]}
    raw = tag.string
    if not raw or not raw.strip():
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Intigriti: empty scope data block"]}
    try:
        data = json.loads(raw)
        prog = data.get("program", {})
    except json.JSONDecodeError:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["Intigriti: failed to parse scope data"]}

    domains = prog.get("domains", {})
    in_scope_raw = [
        {"asset_type": d.get("type", "url"), "asset_value": d.get("value", ""),
         "eligible_for_bounty": d.get("eligible_for_bounty", True)}
        for d in domains.get("in_scope", [])
    ]
    out_of_scope_raw = [
        {"asset_type": d.get("type", "url"), "asset_value": d.get("value", ""),
         "eligible_for_bounty": False}
        for d in domains.get("out_of_scope", [])
    ]
    return {
        "program_name": prog.get("name", ""),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": prog.get("policy", ""),
        "_warnings": [],
    }


async def _fetch_yeswehack(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url, headers=_BROWSER_HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    tag = soup.find("script", {"id": "__NUXT_DATA__"})
    if not tag:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["YesWeHack: could not find data block"]}
    raw = tag.string
    if not raw or not raw.strip():
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["YesWeHack: empty data block"]}
    try:
        data = json.loads(raw)
        prog = data.get("program", {})
    except json.JSONDecodeError:
        return {"program_name": "", "in_scope_raw": [], "out_of_scope_raw": [],
                "guidelines": "", "_warnings": ["YesWeHack: failed to parse program data"]}

    in_scope_raw, out_of_scope_raw = [], []
    for s in prog.get("scopes", []):
        entry = {
            "asset_type": s.get("scope_type", "web_application"),
            "asset_value": s.get("asset", ""),
            "eligible_for_bounty": s.get("eligible_bounty", False),
        }
        if s.get("out_of_scope", False):
            out_of_scope_raw.append(entry)
        else:
            in_scope_raw.append(entry)

    return {
        "program_name": prog.get("title", ""),
        "in_scope_raw": in_scope_raw,
        "out_of_scope_raw": out_of_scope_raw,
        "guidelines": prog.get("guidelines", ""),
        "_warnings": [],
    }


def _parse_policy(raw: dict, platform: str, handle: str) -> EngagementResult:
    """Convert a normalised raw dict from any _fetch_* function into EngagementResult."""
    warnings: list[str] = list(raw.get("_warnings", []))

    in_scope = [
        ScopeEntry(
            asset_type=e.get("asset_type", "unknown"),
            asset_value=e.get("asset_value", ""),
            eligible_for_bounty=e.get("eligible_for_bounty", True),
        )
        for e in raw.get("in_scope_raw", [])
        if e.get("asset_value")
    ]
    out_of_scope_entries = [
        ScopeEntry(
            asset_type=e.get("asset_type", "unknown"),
            asset_value=e.get("asset_value", ""),
            eligible_for_bounty=False,
        )
        for e in raw.get("out_of_scope_raw", [])
        if e.get("asset_value")
    ]

    guidelines = raw.get("guidelines", "")

    # Parse rate limit
    rate_limit: int | None = None
    m = _RATE_LIMIT_RE.search(guidelines)
    if m:
        val = int(m.group(1))
        unit = m.group(2).lower()
        rate_limit = val if unit.startswith("s") else max(1, val // 60)

    # Parse custom headers
    custom_headers: dict[str, str] = {}
    for hm in _CUSTOM_HEADER_RE.finditer(guidelines):
        custom_headers[hm.group(1).strip()] = hm.group(2).strip()

    if not in_scope and not out_of_scope_entries:
        warnings.append("Scope data could not be parsed — fill manually")

    return EngagementResult(
        platform=platform,
        handle=handle,
        program_name=raw.get("program_name", ""),
        in_scope=in_scope,
        out_of_scope_entries=out_of_scope_entries,
        rate_limit=rate_limit,
        custom_headers=custom_headers,
        guidelines=guidelines,
        stage_rules=[],
        parse_warnings=warnings,
    )


# ---------------------------------------------------------------------------
# EngagementMapper — pure transformation, no I/O
# ---------------------------------------------------------------------------

class EngagementMapper:
    """Convert EngagementResult -> CampaignFormPrefill using keyword map + optional LLM."""

    _SEED_TYPES = {"domain", "wildcard", "url"}
    _SCOPE_TYPES = {"domain", "wildcard", "url", "cidr"}

    def map(self, result: EngagementResult) -> CampaignFormPrefill:
        seed_targets = [
            e.asset_value for e in result.in_scope
            if e.asset_type.lower() in self._SEED_TYPES and e.asset_value
        ]
        in_scope = [
            e.asset_value for e in result.in_scope
            if e.asset_type.lower() in self._SCOPE_TYPES and e.asset_value
        ]
        out_of_scope = [
            e.asset_value for e in result.out_of_scope_entries
            if e.asset_value
        ]

        conditional_stages = self._apply_keyword_map(result.guidelines)

        return CampaignFormPrefill(
            program_name=result.program_name,
            seed_targets=seed_targets,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rate_limit=result.rate_limit if result.rate_limit is not None else 50,
            custom_headers=result.custom_headers,
            guidelines=result.guidelines,
            conditional_stages=conditional_stages,
            parse_warnings=list(result.parse_warnings),
        )

    def _apply_keyword_map(self, text: str) -> dict[str, dict]:
        """Pass 1: keyword scan to find disallowed attack types."""
        lower = text.lower()
        result: dict[str, dict] = {}
        for stage, keywords in ATTACK_KEYWORD_MAP.items():
            for kw in keywords:
                idx = lower.find(kw.lower())
                if idx == -1:
                    continue
                # Check for negation in the 40 chars before the keyword
                context_before = lower[max(0, idx - 40): idx]
                if not any(neg in context_before for neg in ("no ", "not ", "prohibit", "disallow", "forbidden", "avoid", "do not")):
                    continue
                # Check for exception clause in the 100 chars after the keyword
                context_after = text[idx + len(kw): idx + len(kw) + 100]
                chain_exception = bool(_EXCEPTION_RE.search(context_after))
                if stage not in result:
                    result[stage] = {
                        "out_of_scope": True,
                        "chain_exception": chain_exception,
                        "reason": f"Policy mentions: '{kw}'",
                    }
                    if chain_exception:
                        break  # already True; no further keywords can upgrade further
                elif chain_exception and not result[stage]["chain_exception"]:
                    result[stage]["chain_exception"] = True
                    break  # upgraded to True; stop scanning
        return result

    async def apply_llm_pass(
        self, result: EngagementResult, prefill: CampaignFormPrefill
    ) -> CampaignFormPrefill:
        """Pass 2: LLM enrichment — fills gaps the keyword map missed."""
        from lib_webbh.llm_client import LLMClient
        import json as _json

        client = LLMClient()
        prompt = (
            "You are a bug bounty rules parser. Given the following program policy text, "
            "return a JSON array of attack types that are out of scope. "
            "For each, include: stage (from this list: "
            + ", ".join(ATTACK_KEYWORD_MAP.keys())
            + "), out_of_scope (true), chain_exception (true if the policy says the attack "
            "is allowed if it proves deeper/critical impact, else false), reason (short quote). "
            "Return ONLY valid JSON. Policy:\n\n"
            + result.guidelines
        )
        try:
            response = await client.generate(prompt, json_mode=True, temperature=0.1)
            rules = _json.loads(response.text)
            if not isinstance(rules, list):
                raise ValueError("LLM returned non-list")
        except Exception:
            prefill.parse_warnings.append("LLM enrichment unavailable — keyword map only")
            return prefill

        for rule in rules:
            stage = rule.get("stage", "")
            if stage not in ATTACK_KEYWORD_MAP:
                continue
            if stage in prefill.conditional_stages:
                continue  # keyword map takes precedence
            prefill.conditional_stages[stage] = {
                "out_of_scope": bool(rule.get("out_of_scope", True)),
                "chain_exception": bool(rule.get("chain_exception", False)),
                "reason": str(rule.get("reason", "")),
            }
        return prefill


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

async def search_programs(
    platform: str,
    company_name: str,
    credentials: dict | None = None,
) -> list[ProgramCandidate]:
    """Phase 1 — find matching programs by company name on the given platform."""
    creds = credentials or {}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        if platform == "hackerone":
            return await _search_hackerone(client, company_name, creds)
        elif platform == "bugcrowd":
            return await _search_bugcrowd(client, company_name)
        elif platform == "intigriti":
            return await _search_intigriti(client, company_name)
        elif platform == "yeswehack":
            return await _search_yeswehack(client, company_name)
        else:
            raise ValueError(f"Unsupported platform: {platform!r}")


async def fetch_engagement(
    platform: str,
    handle: str,
    url: str,
    credentials: dict | None = None,
    use_llm: bool = True,
) -> CampaignFormPrefill:
    """Phase 2 — fetch full policy for a known program and map to CampaignFormPrefill."""
    creds = credentials or {}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        if platform == "hackerone":
            raw = await _fetch_hackerone(client, handle, creds)
        elif platform == "bugcrowd":
            raw = await _fetch_bugcrowd(client, url)
        elif platform == "intigriti":
            raw = await _fetch_intigriti(client, url)
        elif platform == "yeswehack":
            raw = await _fetch_yeswehack(client, url)
        else:
            raise ValueError(f"Unsupported platform: {platform!r}")

    engagement = _parse_policy(raw, platform, handle)
    mapper = EngagementMapper()
    prefill = mapper.map(engagement)
    if use_llm:
        prefill = await mapper.apply_llm_pass(engagement, prefill)
    return prefill
