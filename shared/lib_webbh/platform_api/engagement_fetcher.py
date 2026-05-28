"""Find Engagement — two-phase platform lookup and policy parser.

Phase 1 (search_programs): company name -> list[ProgramCandidate]
Phase 2 (fetch_engagement): program URL/handle -> EngagementResult -> CampaignFormPrefill
"""
from __future__ import annotations

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
