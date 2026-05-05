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
    classification: Optional[str] = None  # "in-scope" | "out-of-scope" | "pending"
    matched_pattern: Optional[str] = None


class ScopeManager:
    """Evaluate whether assets belong to the engagement scope.

    Can be initialized two ways:

    1. Legacy (target_profile dict):
       ScopeManager(target_profile={
           "in_scope_domains": ["*.example.com"],
           "out_scope_domains": ["staging.example.com"],
           "in_scope_cidrs": ["192.168.0.0/16"],
           "in_scope_regex": [r".*\\.internal\\.corp$"],
       })

    2. New (raw pattern lists):
       ScopeManager(
           in_scope=["*.example.com", "example.com", "10.0.0.0/8"],
           out_of_scope=["staging.example.com", "example.com/api/v1/internal/*"],
       )
    """

    def __init__(
        self,
        target_profile: dict | None = None,
        *,
        in_scope: list[str] | None = None,
        out_of_scope: list[str] | None = None,
    ) -> None:
        self._in_domains: list[str] = []
        self._in_exact_domains: list[str] = []
        self._out_domains: list[str] = []
        self._in_networks: list[netaddr.IPNetwork] = []
        self._regex_rules: list[re.Pattern] = []
        # Raw patterns for the wildcard-based classify() path
        self._in_scope_patterns: list[str] = []
        self._out_of_scope_patterns: list[str] = []

        if in_scope is not None or out_of_scope is not None:
            # New-style initialization with raw patterns
            self._in_scope_patterns = list(in_scope or [])
            self._out_of_scope_patterns = list(out_of_scope or [])
            # Also populate legacy fields for is_in_scope() compatibility
            self._populate_legacy_from_patterns(self._in_scope_patterns, self._out_of_scope_patterns)
        elif target_profile is not None:
            # Legacy initialization
            self._populate_legacy_from_profile(target_profile)

    def _populate_legacy_from_profile(self, target_profile: dict) -> None:
        for domain in target_profile.get("in_scope_domains", []):
            if domain.startswith("*."):
                self._in_domains.append(domain[2:].lower())
            else:
                self._in_exact_domains.append(domain.lower())

        for domain in target_profile.get("out_scope_domains", []):
            self._out_domains.append(domain.lower())

        for cidr in target_profile.get("in_scope_cidrs", []):
            self._in_networks.append(netaddr.IPNetwork(cidr))

        for pattern in target_profile.get("in_scope_regex", []):
            self._regex_rules.append(re.compile(pattern))

    def _populate_legacy_from_patterns(self, in_patterns: list[str], out_patterns: list[str]) -> None:
        from lib_webbh.wildcard import _IP_PATTERN

        for p in in_patterns:
            if "/" in p and not _IP_PATTERN.match(p):
                continue  # path pattern — no legacy equivalent
            try:
                net = netaddr.IPNetwork(p)
                self._in_networks.append(net)
                continue
            except (netaddr.AddrFormatError, ValueError):
                pass
            if _IP_PATTERN.match(p):
                continue  # IP wildcard — handled by classify() only
            if p.startswith("*.") or p.startswith("**."):
                self._in_domains.append(p.lstrip("*").lstrip(".").lower())
            else:
                self._in_exact_domains.append(p.lower())

        for p in out_patterns:
            if "/" in p:
                continue  # path exclusion — handled by classify() only
            self._out_domains.append(p.lower())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(self, value: str) -> ScopeResult:
        """Classify a value as in-scope, out-of-scope, or pending.

        Uses the wildcard pattern engine for matching. Checks out-of-scope
        patterns first (exclusions always win).

        Returns ScopeResult with classification and matched_pattern fields.
        """
        from lib_webbh.wildcard import match_pattern

        # 1. Check out-of-scope patterns first
        for pattern in self._out_of_scope_patterns:
            if match_pattern(value, pattern):
                return ScopeResult(
                    in_scope=False,
                    original=value,
                    normalized=value.lower(),
                    asset_type=self._detect_type(value),
                    classification="out-of-scope",
                    matched_pattern=pattern,
                )

        # 2. Check in-scope patterns
        for pattern in self._in_scope_patterns:
            if match_pattern(value, pattern):
                return ScopeResult(
                    in_scope=True,
                    original=value,
                    normalized=value.lower(),
                    asset_type=self._detect_type(value),
                    classification="in-scope",
                    matched_pattern=pattern,
                )

        # 3. No match → pending (needs deep classification)
        return ScopeResult(
            in_scope=False,
            original=value,
            normalized=value.lower(),
            asset_type=self._detect_type(value),
            classification="pending",
            matched_pattern=None,
        )

    @staticmethod
    def _detect_type(value: str) -> str:
        from lib_webbh.wildcard import _IP_PATTERN
        if _IP_PATTERN.match(value):
            return "ip"
        if "/" in value:
            return "domain"
        return "domain"

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


async def record_scope_violation(
    target_id: int, tool_name: str, input_value: str, violation_type: str
) -> None:
    """Persist a scope violation to the database."""
    from lib_webbh.database import get_session, ScopeViolation

    async with get_session() as session:
        sv = ScopeViolation(
            target_id=target_id,
            tool_name=tool_name,
            input_value=input_value,
            violation_type=violation_type,
        )
        session.add(sv)
        await session.commit()
