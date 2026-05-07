"""Built-in campaign playbooks for WebAppBH.

Each playbook defines which pipeline workers and stages are enabled,
tool-specific parameters, and concurrency settings.  The hierarchical
model maps 15 pipeline workers to their ordered stage lists.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


# ---------------------------------------------------------------------------
# Pipeline stage registry — maps each worker to its ordered stage names
# ---------------------------------------------------------------------------
PIPELINE_STAGES: dict[str, list[str]] = {
    "info_gathering": [
        "search_engine_recon", "web_server_fingerprint", "web_server_metafiles",
        "enumerate_subdomains", "review_comments", "identify_entry_points",
        "map_execution_paths", "fingerprint_framework", "map_architecture",
        "map_application",
    ],
    "config_mgmt": [
        "network_config", "platform_config", "file_extension_handling",
        "backup_files", "api_discovery", "http_methods", "hsts_testing",
        "rpc_testing", "file_inclusion", "subdomain_takeover", "cloud_storage",
    ],
    "identity_mgmt": [
        "role_definitions", "registration_process", "account_provisioning",
        "account_enumeration", "weak_username_policy",
    ],
    "authentication": [
        "credentials_transport", "default_credentials", "lockout_mechanism",
        "auth_bypass", "remember_password", "browser_cache",
        "weak_password_policy", "security_questions", "password_change",
        "multi_channel_auth",
    ],
    "authorization": [
        "directory_traversal", "authz_bypass", "privilege_escalation", "idor",
    ],
    "session_mgmt": [
        "session_scheme", "cookie_attributes", "session_fixation",
        "exposed_variables", "csrf", "logout_functionality", "session_timeout",
        "session_puzzling", "session_hijacking",
    ],
    "input_validation": [
        "reflected_xss", "stored_xss", "http_verb_tampering",
        "http_param_pollution", "sql_injection", "ldap_injection",
        "xml_injection", "ssti", "xpath_injection", "imap_smtp_injection",
        "code_injection", "command_injection", "format_string",
        "host_header_injection", "ssrf", "file_inclusion", "buffer_overflow",
        "http_smuggling", "websocket_injection",
    ],
    "error_handling": ["error_codes", "stack_traces"],
    "cryptography": [
        "tls_testing", "padding_oracle", "plaintext_transmission", "weak_crypto",
    ],
    "business_logic": [
        "data_validation", "request_forgery", "integrity_checks",
        "process_timing", "rate_limiting", "workflow_bypass",
        "application_misuse", "file_upload_validation", "malicious_file_upload",
    ],
    "client_side": [
        "dom_xss", "clickjacking", "csrf_tokens", "csp_bypass",
        "html5_injection", "web_storage", "client_side_logic",
        "dom_based_injection", "client_side_resource_manipulation",
        "client_side_auth", "xss_client_side", "css_injection",
        "malicious_upload_client",
    ],
    "mobile_worker": [
        "acquire_decompile", "secret_extraction", "configuration_audit",
        "dynamic_analysis", "endpoint_feedback",
    ],
    "reasoning_worker": [
        "finding_correlation", "impact_analysis", "chain_hypothesis",
    ],
    "chain_worker": [
        "data_collection", "chain_evaluation", "ai_chain_discovery",
        "chain_execution", "reporting",
    ],
    "reporting": [
        "data_gathering", "deduplication", "rendering", "export",
    ],
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class ConcurrencyConfig:
    heavy: int = 2
    light: int = 4


@dataclass
class StageConfig:
    name: str
    enabled: bool = True
    tool_timeout: int = 600  # seconds


@dataclass
class WorkerConfig:
    name: str
    enabled: bool = True
    stages: list[StageConfig] = field(default_factory=list)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)


@dataclass
class PlaybookConfig:
    name: str
    description: str
    workers: list[WorkerConfig] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def build_worker_config(
    worker_name: str,
    *,
    enabled: bool = True,
    disabled_stages: list[str] | None = None,
    concurrency: ConcurrencyConfig | None = None,
    stage_timeouts: dict[str, int] | None = None,
) -> WorkerConfig:
    """Build a WorkerConfig for the named pipeline worker."""
    disabled = set(disabled_stages or [])
    timeouts = stage_timeouts or {}
    stages = [
        StageConfig(
            name=s,
            enabled=s not in disabled,
            tool_timeout=timeouts.get(s, 600),
        )
        for s in PIPELINE_STAGES[worker_name]
    ]
    return WorkerConfig(
        name=worker_name,
        enabled=enabled,
        stages=stages,
        concurrency=concurrency or ConcurrencyConfig(),
    )


def get_worker_stages(playbook: dict | None, worker_name: str) -> list[dict] | None:
    """Extract stages for a worker from a serialized playbook dict."""
    if not playbook or "workers" not in playbook:
        return None
    for w in playbook["workers"]:
        if w["name"] == worker_name:
            if not w.get("enabled", True):
                return []
            return w.get("stages", [])
    return []


# ---------------------------------------------------------------------------
# All 15 worker names (convenience)
# ---------------------------------------------------------------------------
_ALL_WORKERS = list(PIPELINE_STAGES.keys())


def _build_all_workers(
    *,
    disabled_workers: list[str] | None = None,
    worker_overrides: dict[str, dict] | None = None,
    default_concurrency: ConcurrencyConfig | None = None,
) -> list[WorkerConfig]:
    """Build WorkerConfig for all 15 workers with optional overrides.

    *worker_overrides* maps worker name -> kwargs for ``build_worker_config``
    (excluding ``worker_name``).  Any worker not listed gets defaults.
    """
    disabled = set(disabled_workers or [])
    overrides = worker_overrides or {}
    default_cc = default_concurrency or ConcurrencyConfig()
    workers: list[WorkerConfig] = []
    for name in _ALL_WORKERS:
        kw = overrides.get(name, {})
        if name in disabled:
            kw.setdefault("enabled", False)
        kw.setdefault("concurrency", default_cc)
        workers.append(build_worker_config(name, **kw))
    return workers


# ---------------------------------------------------------------------------
# Built-in playbooks
# ---------------------------------------------------------------------------
BUILTIN_PLAYBOOKS: dict[str, PlaybookConfig] = {
    # -- wide_recon: all workers, all stages, high concurrency ---------------
    "wide_recon": PlaybookConfig(
        name="wide_recon",
        description=(
            "Full pipeline with all 15 workers enabled. "
            "Best for large targets with many subdomains."
        ),
        workers=_build_all_workers(
            default_concurrency=ConcurrencyConfig(heavy=2, light=8),
        ),
    ),

    # -- deep_webapp: mobile disabled, info_gathering trimmed, input_validation/session boosted
    "deep_webapp": PlaybookConfig(
        name="deep_webapp",
        description=(
            "Focused on web application testing. "
            "Disables mobile worker, boosts input_validation and session_mgmt concurrency."
        ),
        workers=_build_all_workers(
            disabled_workers=["mobile_worker"],
            worker_overrides={
                "info_gathering": {
                    "disabled_stages": ["search_engine_recon", "enumerate_subdomains"],
                },
                "input_validation": {
                    "concurrency": ConcurrencyConfig(heavy=3, light=6),
                },
                "session_mgmt": {
                    "concurrency": ConcurrencyConfig(heavy=3, light=6),
                },
            },
        ),
    ),

    # -- api_focused: client_side/mobile/session disabled, info_gathering partial
    "api_focused": PlaybookConfig(
        name="api_focused",
        description=(
            "Minimal recon, maximum parameter discovery. "
            "For targets with known API surface."
        ),
        workers=_build_all_workers(
            disabled_workers=["client_side", "mobile_worker", "session_mgmt"],
            default_concurrency=ConcurrencyConfig(heavy=1, light=4),
            worker_overrides={
                "info_gathering": {
                    "disabled_stages": [
                        "search_engine_recon", "web_server_metafiles",
                        "enumerate_subdomains", "review_comments",
                        "fingerprint_framework", "map_architecture",
                    ],
                },
            },
        ),
    ),

    # -- cloud_first: all workers, config_mgmt timeouts, info_gathering concurrency
    "cloud_first": PlaybookConfig(
        name="cloud_first",
        description=(
            "Full pipeline plus aggressive cloud enumeration. "
            "For targets with significant cloud footprint."
        ),
        workers=_build_all_workers(
            worker_overrides={
                "config_mgmt": {
                    "stage_timeouts": {
                        "cloud_storage": 900,
                        "api_discovery": 900,
                    },
                },
                "info_gathering": {
                    "concurrency": ConcurrencyConfig(heavy=3, light=8),
                },
            },
        ),
    ),
}

DEFAULT_PLAYBOOK = "wide_recon"


def get_playbook(name: str) -> PlaybookConfig:
    """Return a playbook config by name, falling back to the default."""
    return BUILTIN_PLAYBOOKS.get(name, BUILTIN_PLAYBOOKS[DEFAULT_PLAYBOOK])
