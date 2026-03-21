"""Shared infrastructure fingerprinting.

Identifies whether a domain or IP belongs to shared/hosted infrastructure
(CDNs, cloud providers, SaaS platforms) so that scanners can deprioritise
or skip assets that are not exclusively controlled by the target.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import netaddr


@dataclass
class InfraClassification:
    """Result of a shared-infrastructure check."""

    is_shared: bool
    provider: Optional[str] = None
    category: Optional[str] = None


# (domain_suffix, provider_name, category)
_SHARED_DOMAINS: list[tuple[str, str, str]] = [
    # --- CDN ---
    ("cloudflare.com", "Cloudflare", "CDN"),
    ("cloudflare-dns.com", "Cloudflare", "CDN"),
    ("cloudfront.net", "AWS", "CDN"),
    ("akamaized.net", "Akamai", "CDN"),
    ("akamaihd.net", "Akamai", "CDN"),
    ("fastly.net", "Fastly", "CDN"),
    ("edgecastcdn.net", "Edgecast", "CDN"),
    ("azureedge.net", "Azure", "CDN"),
    # --- Cloud ---
    ("googleapis.com", "Google", "Cloud"),
    ("s3.amazonaws.com", "AWS", "Cloud"),
    ("amazonaws.com", "AWS", "Cloud"),
    ("azure-api.net", "Azure", "Cloud"),
    ("blob.core.windows.net", "Azure", "Cloud"),
    ("appspot.com", "Google", "Cloud"),
    ("firebaseapp.com", "Google", "Cloud"),
    # --- Hosting ---
    ("herokuapp.com", "Heroku", "Hosting"),
    ("netlify.app", "Netlify", "Hosting"),
    ("vercel.app", "Vercel", "Hosting"),
    ("pages.dev", "Cloudflare", "Hosting"),
    # --- SaaS ---
    ("zendesk.com", "Zendesk", "SaaS"),
    ("freshdesk.com", "Freshworks", "SaaS"),
    ("intercom.io", "Intercom", "SaaS"),
    ("statuspage.io", "Atlassian", "SaaS"),
    ("atlassian.net", "Atlassian", "SaaS"),
    ("hubspot.com", "HubSpot", "SaaS"),
    ("mailchimp.com", "Mailchimp", "SaaS"),
    ("shopify.com", "Shopify", "SaaS"),
    ("myshopify.com", "Shopify", "SaaS"),
    ("wordpress.com", "WordPress", "SaaS"),
    ("wixsite.com", "Wix", "SaaS"),
    ("squarespace.com", "Squarespace", "SaaS"),
]

# (CIDR, provider_name) — well-known shared-infra IP ranges
_SHARED_CIDRS: list[tuple[str, str]] = [
    ("104.16.0.0/12", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("131.0.72.0/22", "Cloudflare"),
    ("13.32.0.0/15", "AWS CloudFront"),
    ("52.84.0.0/15", "AWS CloudFront"),
    ("99.84.0.0/16", "AWS CloudFront"),
    ("23.0.0.0/12", "Akamai"),
    ("151.101.0.0/16", "Fastly"),
]

# Pre-parsed networks for fast lookup at import time
_SHARED_NETWORKS = [
    (netaddr.IPNetwork(cidr), provider) for cidr, provider in _SHARED_CIDRS
]


def is_shared_infra(item: str) -> InfraClassification:
    """Classify a domain or IP as shared infrastructure.

    Args:
        item: A domain name (e.g. ``cdn.cloudflare.com``) or an IPv4/IPv6
              address (e.g. ``104.16.0.1``).

    Returns:
        An :class:`InfraClassification` indicating whether the item belongs
        to a known shared-infrastructure provider.
    """
    item_lower = item.lower().strip()

    # --- Try IP-based lookup first ---
    try:
        ip = netaddr.IPAddress(item_lower)
        for network, provider in _SHARED_NETWORKS:
            if ip in network:
                return InfraClassification(
                    is_shared=True, provider=provider, category="CDN"
                )
        return InfraClassification(is_shared=False)
    except (netaddr.AddrFormatError, ValueError):
        pass

    # --- Domain suffix lookup ---
    for suffix, provider, category in _SHARED_DOMAINS:
        if item_lower == suffix or item_lower.endswith(f".{suffix}"):
            return InfraClassification(
                is_shared=True, provider=provider, category=category
            )

    return InfraClassification(is_shared=False)
