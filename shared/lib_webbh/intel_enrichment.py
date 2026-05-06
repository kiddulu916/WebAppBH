"""Intel enrichment via Shodan and SecurityTrails APIs.

Provides async functions that query external intelligence services
for subdomain, IP, and port data. Functions return gracefully with
empty results when API keys are not configured.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

# ---------------------------------------------------------------------------
# Module-level API key reads
# ---------------------------------------------------------------------------
SHODAN_API_KEY: str = os.environ.get("SHODAN_API_KEY", "")
SECURITYTRAILS_API_KEY: str = os.environ.get("SECURITYTRAILS_API_KEY", "")
CENSYS_API_ID: str = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET: str = os.environ.get("CENSYS_API_SECRET", "")

SHODAN_BASE = "https://api.shodan.io"
SECURITYTRAILS_BASE = "https://api.securitytrails.com/v1"

_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------
@dataclass
class IntelResult:
    source: str
    subdomains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    ports: list[dict] = field(default_factory=list)  # {"ip": ..., "port": ..., "service": ...}
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Shodan enrichment
# ---------------------------------------------------------------------------
async def enrich_shodan(domain: str, *, api_key: str | None = None) -> IntelResult:
    """Query Shodan for subdomains, IPs, and open ports on *domain*.

    If no API key is available (env or parameter), returns an empty
    ``IntelResult`` with ``raw={"error": "no_api_key"}``.
    """
    key = api_key or SHODAN_API_KEY
    if not key:
        return IntelResult(source="shodan", raw={"error": "no_api_key"})

    result = IntelResult(source="shodan")

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # DNS resolve endpoint — subdomains
        try:
            dns_resp = await client.get(
                f"{SHODAN_BASE}/dns/domain/{domain}",
                params={"key": key},
            )
            dns_resp.raise_for_status()
            dns_data = dns_resp.json()
            result.raw["dns"] = dns_data

            # Extract subdomains from data array
            for record in dns_data.get("data", []):
                subdomain = record.get("subdomain", "")
                if subdomain and subdomain != "":
                    fqdn = f"{subdomain}.{domain}"
                    if fqdn not in result.subdomains:
                        result.subdomains.append(fqdn)

                # Extract IPs from A records
                value = record.get("value", "")
                rec_type = record.get("type", "")
                if rec_type == "A" and value and value not in result.ips:
                    result.ips.append(value)
        except httpx.HTTPStatusError as exc:
            result.raw["dns_error"] = str(exc)
        except httpx.RequestError as exc:
            result.raw["dns_error"] = str(exc)

        # Host search — open ports per IP
        for ip in list(result.ips):
            try:
                host_resp = await client.get(
                    f"{SHODAN_BASE}/shodan/host/{ip}",
                    params={"key": key},
                )
                host_resp.raise_for_status()
                host_data = host_resp.json()

                for port_entry in host_data.get("data", []):
                    result.ports.append({
                        "ip": ip,
                        "port": port_entry.get("port"),
                        "service": port_entry.get("product", port_entry.get("_shodan", {}).get("module", "unknown")),
                    })
            except (httpx.HTTPStatusError, httpx.RequestError):
                pass  # Best-effort port enrichment

    return result


# ---------------------------------------------------------------------------
# SecurityTrails enrichment
# ---------------------------------------------------------------------------
async def enrich_securitytrails(domain: str, *, api_key: str | None = None) -> IntelResult:
    """Query SecurityTrails for subdomains and DNS records of *domain*.

    If no API key is available, returns an empty ``IntelResult`` with
    ``raw={"error": "no_api_key"}``.
    """
    key = api_key or SECURITYTRAILS_API_KEY
    if not key:
        return IntelResult(source="securitytrails", raw={"error": "no_api_key"})

    result = IntelResult(source="securitytrails")
    headers = {"APIKEY": key, "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        # Subdomains endpoint
        try:
            sub_resp = await client.get(
                f"{SECURITYTRAILS_BASE}/domain/{domain}/subdomains",
            )
            sub_resp.raise_for_status()
            sub_data = sub_resp.json()
            result.raw["subdomains"] = sub_data

            for sub in sub_data.get("subdomains", []):
                fqdn = f"{sub}.{domain}"
                if fqdn not in result.subdomains:
                    result.subdomains.append(fqdn)
        except httpx.HTTPStatusError as exc:
            result.raw["subdomains_error"] = str(exc)
        except httpx.RequestError as exc:
            result.raw["subdomains_error"] = str(exc)

        # DNS records — extract A record IPs
        try:
            dns_resp = await client.get(
                f"{SECURITYTRAILS_BASE}/domain/{domain}",
            )
            dns_resp.raise_for_status()
            dns_data = dns_resp.json()
            result.raw["dns"] = dns_data

            # A records
            a_records = (
                dns_data
                .get("current_dns", {})
                .get("a", {})
                .get("values", [])
            )
            for rec in a_records:
                ip = rec.get("ip", "")
                if ip and ip not in result.ips:
                    result.ips.append(ip)
        except httpx.HTTPStatusError as exc:
            result.raw["dns_error"] = str(exc)
        except httpx.RequestError as exc:
            result.raw["dns_error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Source availability
# ---------------------------------------------------------------------------
def get_available_intel_sources() -> dict[str, bool]:
    """Return which intel sources have API keys configured."""
    return {
        "shodan": bool(SHODAN_API_KEY),
        "securitytrails": bool(SECURITYTRAILS_API_KEY),
        "censys": bool(CENSYS_API_ID) and bool(CENSYS_API_SECRET),
    }
