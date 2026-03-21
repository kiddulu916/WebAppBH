"""Vulnerability report template engine for bug bounty platforms."""
from __future__ import annotations
from enum import Enum


class Platform(Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"


_HACKERONE_TEMPLATE = """## Summary

**Title:** {title}
**Severity:** {severity}
**Affected Asset:** {asset_value}
**CVSS Score:** {cvss_score}

## Description

{description}

## Steps to Reproduce

1. Navigate to the affected asset: `{asset_value}`
2. Apply the following proof of concept:

```
{poc}
```

3. Observe the vulnerability behavior as described above.

## Impact

A {severity}-severity {title} on `{asset_value}` could allow an attacker to compromise the confidentiality, integrity, or availability of the target system. The finding was identified using `{source_tool}`.

## Supporting Material / References

- Tool: `{source_tool}`
- Asset: `{asset_value}`
"""

_BUGCROWD_TEMPLATE = """## Vulnerability: {title}

**Severity:** {severity}
**Asset:** {asset_value}
**CVSS:** {cvss_score}
**Discovery Tool:** {source_tool}

### Description

{description}

### Proof of Concept

```
{poc}
```

### Suggested Remediation

Address the identified {title} on `{asset_value}` by implementing appropriate input validation, output encoding, or access controls as applicable to this vulnerability class.
"""

_TEMPLATES = {
    Platform.HACKERONE: _HACKERONE_TEMPLATE,
    Platform.BUGCROWD: _BUGCROWD_TEMPLATE,
}


def render_vuln_report(vuln: dict, platform: Platform) -> str:
    """Render a vulnerability report for the given platform.

    Args:
        vuln: Dictionary containing vulnerability details. Supported keys:
              title, severity, asset_value, description, poc, source_tool,
              cvss_score. Missing keys default to "N/A".
        platform: Target bug bounty platform (HackerOne or Bugcrowd).

    Returns:
        Formatted markdown report string.
    """
    defaults = {
        "title": "N/A",
        "severity": "N/A",
        "asset_value": "N/A",
        "description": "N/A",
        "poc": "N/A",
        "source_tool": "N/A",
        "cvss_score": "N/A",
    }
    data = {**defaults, **{k: v for k, v in vuln.items() if v is not None}}
    template = _TEMPLATES[platform]
    return template.format(**data)
