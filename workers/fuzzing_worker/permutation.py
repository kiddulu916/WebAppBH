"""Subdomain permutation generator for fuzzing-to-recon handoff."""
from __future__ import annotations

SUFFIXES = ["-api", "-admin", "-staging", "-test", "-v2", "-internal",
            "-dev", "-prod", "-qa", "-uat"]
PREFIXES = ["v1.", "v2.", "new.", "old.", "beta.", "alpha."]

def extract_prefix(fqdn: str, base_domain: str) -> str | None:
    suffix = f".{base_domain}"
    if not fqdn.endswith(suffix):
        return None
    prefix = fqdn[: -len(suffix)]
    return prefix if prefix else None

def generate_permutations(
    prefixes: list[str], base_domain: str,
    existing: set[str] | None = None,
) -> list[str]:
    existing = existing or set()
    candidates: set[str] = set()
    for prefix in prefixes:
        for suffix in SUFFIXES:
            candidates.add(f"{prefix}{suffix}.{base_domain}")
        for pre in PREFIXES:
            candidates.add(f"{pre}{prefix}.{base_domain}")
        if "-" in prefix:
            swapped = prefix.replace("-", ".")
            candidates.add(f"{swapped}.{base_domain}")
        if "." in prefix:
            swapped = prefix.replace(".", "-")
            candidates.add(f"{swapped}.{base_domain}")
    return sorted(candidates - existing)
