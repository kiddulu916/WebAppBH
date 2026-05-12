# workers/info_gathering/fingerprint_signatures.py
"""Static signature tables consumed by Stage 2 probes and the FingerprintAggregator.

These tables are intentionally small and curated. Probes consult them at
matching time; the aggregator consults them when deciding whether to emit
info-leak Vulnerabilities. Update sparingly — every entry should correspond
to a high-trust, low-false-positive signal.
"""
from __future__ import annotations

# Default-error-page signature ids that, when matched, indicate a fully-default
# server/framework error page leaking server internals. The aggregator emits a
# LOW-severity Vulnerability per match. Keep ids stable: they appear in the
# Observation row's ``tech_stack.signature_match`` field.
DEFAULT_ERROR_LEAKERS: frozenset[str] = frozenset({
    "apache-default-404",
    "nginx-default-404",
    "iis-default-404",
    "tomcat-default-404",
    "express-default-404",
    "django-default-debug",
})

# Lowercase header names that, when present on a public response, indicate
# an internal/debug header leaked past the edge. Comparisons are case-insensitive
# at the call site.
INTERNAL_DEBUG_HEADERS: frozenset[str] = frozenset({
    "x-debug",
    "x-debug-token",
    "x-debug-token-link",
    "x-request-id-internal",
    "x-backend-server",
    "x-served-by-internal",
})

# Passive WAF/CDN fingerprints. Header and cookie names are matched
# case-insensitively at the call site (substring match against the
# response header/cookie name).
WAF_PASSIVE_PATTERNS: dict[str, dict[str, list[str]]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
        "cookies": ["__cf_bm", "cf_clearance"],
    },
    "Akamai": {
        "headers": ["akamai-grn", "x-akamai-transformed"],
        "cookies": ["ak_bmsc"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-waf-action"],
        "cookies": [],
    },
    "F5 BIG-IP": {
        "headers": [],
        "cookies": ["BIGipServer"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cookies": [],
    },
}

# Issuer-CN substring → CDN vendor name. The TLSProbe matches case-insensitively.
CDN_CERT_ISSUERS: dict[str, str] = {
    "Cloudflare Inc": "Cloudflare",
    "Amazon": "CloudFront",
    "Akamai": "Akamai",
    "Fastly": "Fastly",
    "Microsoft Azure": "AzureFD",
}
