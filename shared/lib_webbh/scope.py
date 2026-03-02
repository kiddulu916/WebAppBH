"""Scope management for WebAppBH target profiles.

Determines whether a given asset (domain, IP, CIDR, URL) falls within the
defined scope of a bug-bounty or pentest engagement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import netaddr
import tldextract


@dataclass
class ScopeResult:
    """Result of a scope check."""

    in_scope: bool
    original: str
    normalized: str
    asset_type: str  # "domain" | "ip" | "cidr"
    path: Optional[str] = None


class ScopeManager:
    """Evaluate whether assets belong to the engagement scope.

    Parameters
    ----------
    target_profile : dict
        A dictionary with keys:
        - in_scope_domains: list[str]   (e.g. ["*.example.com", "exact.io"])
        - out_scope_domains: list[str]  (e.g. ["admin.example.com"])
        - in_scope_cidrs: list[str]     (e.g. ["192.168.1.0/24"])
        - in_scope_regex: list[str]     (e.g. [r".*\\.internal\\.corp$"])
    """

    def __init__(self, target_profile: dict) -> None:
        self._in_domains: list[str] = []
        self._in_exact_domains: list[str] = []
        self._out_domains: list[str] = []
        self._in_networks: list[netaddr.IPNetwork] = []
        self._regex_rules: list[re.Pattern] = []

        # Parse domain rules
        for domain in target_profile.get("in_scope_domains", []):
            if domain.startswith("*."):
                self._in_domains.append(domain[2:].lower())
            else:
                self._in_exact_domains.append(domain.lower())

        for domain in target_profile.get("out_scope_domains", []):
            self._out_domains.append(domain.lower())

        # Parse CIDR/network rules
        for cidr in target_profile.get("in_scope_cidrs", []):
            self._in_networks.append(netaddr.IPNetwork(cidr))

        # Parse regex rules
        for pattern in target_profile.get("in_scope_regex", []):
            self._regex_rules.append(re.compile(pattern))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, item: str) -> ScopeResult:
        """Check whether *item* is in scope.

        *item* can be a bare domain, a full URL, an IP address, or a CIDR.
        """
        original = item

        # 1. Try IP / CIDR first
        try:
            network = netaddr.IPNetwork(item)
            if "/" in item:
                # Input is a CIDR range
                for scope_net in self._in_networks:
                    # Check if the input CIDR is entirely contained within a scope CIDR
                    if network.network in scope_net and network.broadcast in scope_net:
                        return ScopeResult(
                            in_scope=True,
                            original=original,
                            normalized=item,
                            asset_type="cidr",
                        )
                return ScopeResult(
                    in_scope=False,
                    original=original,
                    normalized=item,
                    asset_type="cidr",
                )
            else:
                # Input is a single IP address
                ip = netaddr.IPAddress(item)
                for scope_net in self._in_networks:
                    if ip in scope_net:
                        return ScopeResult(
                            in_scope=True,
                            original=original,
                            normalized=item,
                            asset_type="ip",
                        )
                return ScopeResult(
                    in_scope=False,
                    original=original,
                    normalized=item,
                    asset_type="ip",
                )
        except (netaddr.AddrFormatError, ValueError):
            pass

        # 2. URL-like input (has ://)
        domain: str = ""
        path: Optional[str] = None

        if "://" in item:
            parsed = urlparse(item)
            domain = parsed.hostname or ""
            domain = domain.lower()
            # Reconstruct path with query string
            raw_path = parsed.path or ""
            if parsed.query:
                raw_path = f"{raw_path}?{parsed.query}"
            if parsed.fragment:
                raw_path = f"{raw_path}#{parsed.fragment}"
            path = raw_path if raw_path else None
        elif "/" in item:
            # Has a slash but no scheme: split on first /
            parts = item.split("/", 1)
            domain = parts[0].lower()
            path = f"/{parts[1]}" if parts[1] else None
        else:
            domain = item.lower()

        # 3. Check out-of-scope domains FIRST (exclusions always win)
        if domain in self._out_domains:
            return ScopeResult(
                in_scope=False,
                original=original,
                normalized=domain,
                asset_type="domain",
                path=path,
            )

        # 4. Check exact domain matches
        if domain in self._in_exact_domains:
            return ScopeResult(
                in_scope=True,
                original=original,
                normalized=domain,
                asset_type="domain",
                path=path,
            )

        # 5. Check wildcard domain matches
        ext = tldextract.extract(domain)
        _top = getattr(ext, "top_domain_under_public_suffix", None)
        if not _top:
            # Fallback: join domain + suffix manually to avoid deprecated property
            _top = f"{ext.domain}.{ext.suffix}" if ext.suffix else ""
        registered_domain = _top.lower() if _top else ""

        for scope_domain in self._in_domains:
            # Match if the registered domain matches the scope domain
            # or if the full domain ends with .{scope_domain}
            if registered_domain == scope_domain or domain.endswith(f".{scope_domain}"):
                return ScopeResult(
                    in_scope=True,
                    original=original,
                    normalized=domain,
                    asset_type="domain",
                    path=path,
                )

        # 6. Fall through to regex rules
        for pattern in self._regex_rules:
            if pattern.search(item):
                return ScopeResult(
                    in_scope=True,
                    original=original,
                    normalized=domain if domain else item,
                    asset_type="domain",
                    path=path,
                )

        # 7. Default: not in scope
        return ScopeResult(
            in_scope=False,
            original=original,
            normalized=domain if domain else item,
            asset_type="domain",
            path=path,
        )

    def add_rule(self, rule: str, *, in_scope: bool = True) -> None:
        """Add a scope rule at runtime.

        Parameters
        ----------
        rule : str
            A domain pattern (``*.domain.com`` or ``exact.domain.com``),
            a CIDR (``10.0.0.0/8``), or a regex pattern.
        in_scope : bool
            If ``True`` the rule is added as in-scope; if ``False`` it is
            added as an out-of-scope exclusion (domains only).
        """
        # Try to interpret as CIDR
        try:
            net = netaddr.IPNetwork(rule)
            if in_scope:
                self._in_networks.append(net)
            return
        except (netaddr.AddrFormatError, ValueError):
            pass

        # Domain pattern
        if rule.startswith("*."):
            domain = rule[2:].lower()
            if in_scope:
                self._in_domains.append(domain)
            else:
                self._out_domains.append(domain)
        else:
            if in_scope:
                self._in_exact_domains.append(rule.lower())
            else:
                self._out_domains.append(rule.lower())

    def get_scope_summary(self) -> dict:
        """Return a serializable summary of all scope rules."""
        return {
            "domains": {
                "wildcard": [f"*.{d}" for d in self._in_domains],
                "exact": list(self._in_exact_domains),
                "excluded": list(self._out_domains),
            },
            "networks": [str(n) for n in self._in_networks],
            "regex": [p.pattern for p in self._regex_rules],
        }
