"""WAF fingerprinting from HTTP response metadata."""

from __future__ import annotations

import re

WAF_SIGNATURES: dict[str, dict] = {
    "cloudflare": {
        "headers": {"server": ["cloudflare"], "cf-ray": None},
        "body_patterns": [r"Attention Required.*Cloudflare"],
        "status_codes": [403, 503],
    },
    "akamai": {
        "headers": {"server": ["AkamaiGHost"]},
        "body_patterns": [r"Reference #\d+\.\w+"],
    },
    "aws_waf": {
        "headers": {"x-amzn-requestid": None},
        "body_patterns": [r"<AccessDenied>"],
    },
    "modsecurity": {
        "body_patterns": [r"Mod_?Security", r"Not Acceptable!"],
        "status_codes": [406, 501],
    },
    "imperva": {
        "headers": {"x-iinfo": None, "x-cdn": ["Incapsula"]},
    },
    "f5_bigip": {
        "cookies": ["TS01", "BIGipServer"],
    },
    "sucuri": {
        "headers": {"server": ["Sucuri/Cloudproxy"], "x-sucuri-id": None},
    },
}


def fingerprint_waf(
    headers: dict[str, str],
    body: str,
    status_code: int,
    cookies: list[str] | None = None,
) -> str | None:
    """Detect WAF type from an HTTP response.

    Returns the WAF name string or ``None`` if no WAF is detected.
    """
    norm_headers = {k.lower(): v for k, v in headers.items()}
    cookies = cookies or []

    best_match: str | None = None
    best_score = 0

    for waf_name, sig in WAF_SIGNATURES.items():
        score = 0
        has_header_or_body = False

        # Header matching (weighted higher — most reliable signal)
        for header_key, expected_values in sig.get("headers", {}).items():
            header_val = norm_headers.get(header_key.lower())
            if header_val is None:
                continue
            if expected_values is None:
                score += 2
                has_header_or_body = True
            else:
                for ev in expected_values:
                    if ev.lower() in header_val.lower():
                        score += 2
                        has_header_or_body = True

        # Body pattern matching
        for pattern in sig.get("body_patterns", []):
            if re.search(pattern, body, re.IGNORECASE):
                score += 2
                has_header_or_body = True

        # Status code matching (weak signal — only boosts, never sufficient alone)
        if status_code in sig.get("status_codes", []):
            score += 1

        # Cookie matching
        for cookie_prefix in sig.get("cookies", []):
            if any(c.startswith(cookie_prefix) for c in cookies):
                score += 2
                has_header_or_body = True

        # Require at least one header/body/cookie match — status code alone is not enough
        if has_header_or_body and score > best_score:
            best_score = score
            best_match = waf_name

    return best_match
