"""Async deep scope classifier with 7-layer inference engine.

Processes assets with scope_classification="pending" after each pipeline stage.
Each layer checks a different signal (DNS, TLS, HTTP, ASN, headers, WHOIS,
discovery lineage) to determine if an asset is associated with in-scope targets.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from typing import Optional

from lib_webbh.wildcard import match_domain


@dataclass
class DeepResult:
    """Result from the deep classification engine."""

    classification: str  # "associated" | "undetermined"
    association_method: Optional[str] = None  # which layer matched
    associated_value: Optional[str] = None  # the in-scope asset it links to


class DeepClassifier:
    """7-layer async classifier for pending assets.

    Layers (checked in order, short-circuits on first match):
    1. Discovery lineage (discovered_from in-scope parent)
    2. Reverse DNS resolution
    3. TLS certificate SAN matching
    4. HTTP hosting header check
    5. ASN ownership matching
    6. HTTP header linkage
    7. (reserved for WHOIS — not implemented yet)
    """

    TIMEOUT = 5  # seconds per network call

    def __init__(
        self,
        in_scope_domains: list[str],
        in_scope_ips: list[str] | None = None,
    ) -> None:
        self._in_scope_domains = in_scope_domains
        self._in_scope_ips = in_scope_ips or []

    async def classify_deep(
        self,
        value: str,
        asset_type: str,
        discovered_from_scope: str | None = None,
    ) -> DeepResult:
        """Run all classification layers and return the result."""
        # Layer 7 (checked first for speed — no network call needed):
        # Asset discovered from an in-scope parent
        if discovered_from_scope == "in-scope":
            return DeepResult(
                classification="associated",
                association_method="discovered_from",
                associated_value=value,
            )

        # Layer 2: Reverse DNS
        rdns = await reverse_dns(value)
        if rdns and self._domain_matches_scope(rdns):
            return DeepResult(
                classification="associated",
                association_method="dns_resolution",
                associated_value=rdns,
            )

        # Layer 3: TLS SANs
        sans = await get_tls_sans(value)
        for san in sans:
            if self._domain_matches_scope(san):
                return DeepResult(
                    classification="associated",
                    association_method="tls_san",
                    associated_value=san,
                )

        # Layer 4: HTTP hosting
        hosted_domain = await check_http_hosting(value)
        if hosted_domain and self._domain_matches_scope(hosted_domain):
            return DeepResult(
                classification="associated",
                association_method="http_hosting",
                associated_value=hosted_domain,
            )

        # Layer 5: ASN ownership
        asn_info = await lookup_asn(value)
        if asn_info:
            return DeepResult(
                classification="associated",
                association_method="asn_match",
                associated_value=asn_info,
            )

        # Layer 6: Header linkage
        header_link = await check_header_linkage(value)
        if header_link and self._domain_matches_scope(header_link):
            return DeepResult(
                classification="associated",
                association_method="header_linkage",
                associated_value=header_link,
            )

        # No layer matched
        return DeepResult(classification="undetermined")

    def _domain_matches_scope(self, domain: str) -> bool:
        """Check if a domain matches any in-scope domain pattern."""
        for pattern in self._in_scope_domains:
            if match_domain(domain, pattern):
                return True
        return False


# ---------------------------------------------------------------------------
# Network helper functions (module-level for easy mocking in tests)
# ---------------------------------------------------------------------------


async def reverse_dns(ip: str) -> str | None:
    """Reverse-resolve an IP address to a hostname. Returns None on failure."""
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=DeepClassifier.TIMEOUT,
        )
        return result[0]
    except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
        return None


async def get_tls_sans(host: str) -> list[str]:
    """Fetch TLS certificate SANs for a host. Returns empty list on failure."""
    try:

        def _fetch_sans():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(DeepClassifier.TIMEOUT)
                s.connect((host, 443))
                cert = s.getpeercert(binary_form=False)
                if not cert:
                    return []
                sans = []
                for entry_type, entry_value in cert.get("subjectAltName", []):
                    if entry_type == "DNS":
                        sans.append(entry_value)
                return sans

        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_sans),
            timeout=DeepClassifier.TIMEOUT + 2,
        )
    except (ssl.SSLError, socket.error, asyncio.TimeoutError, OSError):
        return []


async def check_http_hosting(ip: str) -> str | None:
    """Check if an IP serves HTTP content for an in-scope domain. Returns domain or None."""
    # Placeholder — real implementation would send HTTP requests with various Host headers
    return None


async def lookup_asn(ip: str) -> str | None:
    """Look up ASN for an IP. Returns ASN string or None."""
    # Placeholder — real implementation would query Team Cymru or similar
    return None


async def check_header_linkage(host: str) -> str | None:
    """Check HTTP response headers for links to in-scope domains. Returns domain or None."""
    # Placeholder — real implementation would check Location, CSP, CORS headers
    return None
