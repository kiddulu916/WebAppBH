"""6-layer async deep scope classifier for pending assets.

Layers (short-circuit on first match):
1. Discovery provenance — discovered from an in-scope parent asset (checked first, free)
2. Reverse DNS — IP resolves to in-scope domain
3. TLS SAN — certificate names match in-scope domain
4. HTTP hosting — HTTP response indicates shared hosting with in-scope target
5. ASN lookup — same ASN as known in-scope IPs
6. Header linkage — response headers reference in-scope domain
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Optional

_log = logging.getLogger("deep-classifier")


@dataclass
class DeepResult:
    """Result of deep classification."""
    classification: str  # "associated" | "undetermined"
    association_method: Optional[str] = None
    associated_value: Optional[str] = None


async def reverse_dns(ip: str) -> Optional[str]:
    """Reverse DNS lookup. Returns hostname or None."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=5,
        )
        return result[0] if result else None
    except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
        return None


async def get_tls_sans(host: str, port: int = 443) -> list[str]:
    """Get TLS certificate Subject Alternative Names. Returns list of names."""
    loop = asyncio.get_event_loop()

    def _fetch_sans():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        return []
                    sans = []
                    for entry_type, entry_value in cert.get("subjectAltName", []):
                        if entry_type == "DNS":
                            sans.append(entry_value)
                    return sans
        except (OSError, ssl.SSLError):
            return []

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_sans),
            timeout=10,
        )
    except asyncio.TimeoutError:
        return []


async def check_http_hosting(host: str) -> Optional[str]:
    """Check HTTP response for hosting indicators. Returns domain found or None."""
    try:
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"https://{host}", allow_redirects=True, ssl=False) as resp:
                # Check if redirected to an in-scope domain
                final_host = resp.url.host
                if final_host and final_host != host:
                    return final_host
    except Exception as exc:
        _log.debug("HTTP hosting check failed for %s: %s", host, exc)
    return None


async def lookup_asn(ip: str) -> Optional[str]:
    """Look up ASN for an IP. Returns ASN string or None."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _whois_asn, ip),
            timeout=5,
        )
        return result
    except asyncio.TimeoutError:
        return None


def _whois_asn(ip: str) -> Optional[str]:
    """Synchronous ASN lookup via DNS TXT query to Team Cymru.

    Uses ``dig +short TXT`` to resolve the TXT record which has the format:
    ``"ASN | prefix | CC | registry | date"``
    Returns the ASN string (e.g. "13335") or None on failure.
    """
    import subprocess
    try:
        octets = ip.split(".")
        query = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
        result = subprocess.run(
            ["dig", "+short", "TXT", query],
            capture_output=True, text=True, timeout=5,
        )
        txt = result.stdout.strip().strip('"')
        if not txt or "|" not in txt:
            return None
        # Format: "ASN | prefix | CC | registry | date"
        asn = txt.split("|")[0].strip()
        return asn if asn.isdigit() else None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


async def check_header_linkage(host: str) -> Optional[str]:
    """Check HTTP response headers for references to other domains."""
    try:
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"https://{host}", allow_redirects=False, ssl=False) as resp:
                # Check Location header for redirects
                location = resp.headers.get("Location", "")
                if location and "://" in location:
                    from urllib.parse import urlparse
                    parsed = urlparse(location)
                    if parsed.hostname and parsed.hostname != host:
                        return parsed.hostname
                # Check CSP header for domain references
                csp = resp.headers.get("Content-Security-Policy", "")
                if csp:
                    # Extract domains from CSP directives
                    for part in csp.split():
                        if "." in part and not part.startswith("'"):
                            part = part.strip(";")
                            if part.count(".") >= 1 and not part.startswith("http"):
                                return part
    except Exception as exc:
        _log.debug("Header linkage check failed for %s: %s", host, exc)
    return None


class DeepClassifier:
    """Async deep scope classifier using 6 inference layers."""

    def __init__(
        self,
        in_scope_domains: list[str] | None = None,
        in_scope_ips: list[str] | None = None,
    ) -> None:
        self._domains = [d.lower().lstrip("*.") for d in (in_scope_domains or [])]
        self._ips = list(in_scope_ips or [])
        # Pre-resolve ASNs of known in-scope IPs for Layer 4 matching
        self._in_scope_asns: set[str] = set()
        for ip in self._ips:
            asn = _whois_asn(ip)
            if asn:
                self._in_scope_asns.add(asn)

    def _matches_scope(self, value: str) -> bool:
        """Check if a value matches any known in-scope domain."""
        value = value.lower()
        for d in self._domains:
            if value == d or value.endswith("." + d):
                return True
        return False

    async def classify_deep(
        self,
        value: str,
        asset_type: str = "ip",
        discovered_from_scope: Optional[str] = None,
    ) -> DeepResult:
        """Run all classification layers, short-circuit on first match.

        Parameters
        ----------
        value : str
            The asset value to classify (IP address, domain, etc.)
        asset_type : str
            The asset type ("ip", "domain", etc.)
        discovered_from_scope : str | None
            If the asset was discovered from another asset, pass the parent's
            scope_classification. If parent was "in-scope", child is "associated".
        """

        # Layer 1: Discovery provenance (checked first since it's free)
        if discovered_from_scope == "in-scope":
            return DeepResult(
                classification="associated",
                association_method="discovered_from",
            )

        # Layer 2: Reverse DNS (IPs only)
        if asset_type == "ip":
            hostname = await reverse_dns(value)
            if hostname and self._matches_scope(hostname):
                return DeepResult(
                    classification="associated",
                    association_method="dns_resolution",
                    associated_value=hostname,
                )

        # Layer 3: TLS SAN check
        try:
            sans = await get_tls_sans(value)
            for san in sans:
                san_clean = san.lstrip("*.")
                if self._matches_scope(san_clean):
                    return DeepResult(
                        classification="associated",
                        association_method="tls_san",
                        associated_value=san,
                    )
        except Exception as exc:
            _log.debug("TLS SAN check failed for %s: %s", value, exc)

        # Layer 4: HTTP hosting check
        redirect_host = await check_http_hosting(value)
        if redirect_host and self._matches_scope(redirect_host):
            return DeepResult(
                classification="associated",
                association_method="http_redirect",
                associated_value=redirect_host,
            )

        # Layer 5: ASN lookup — compare against cached in-scope ASNs
        if asset_type == "ip" and self._in_scope_asns:
            asn = await lookup_asn(value)
            if asn and asn in self._in_scope_asns:
                return DeepResult(
                    classification="associated",
                    association_method="asn_match",
                    associated_value=asn,
                )

        # Layer 6: Header linkage
        header_domain = await check_header_linkage(value)
        if header_domain and self._matches_scope(header_domain):
            return DeepResult(
                classification="associated",
                association_method="header_linkage",
                associated_value=header_domain,
            )

        # All layers exhausted → undetermined
        return DeepResult(
            classification="undetermined",
            association_method=None,
        )
