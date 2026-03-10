"""Maps Nuclei template tags to active injection tools."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolRoute:
    """Mapping from Nuclei tags to a specialised injection tool."""

    tool_name: str
    tag_filters: list[str] = field(default_factory=list)
    severity_escalation: str = "critical"


ROUTES: list[ToolRoute] = [
    ToolRoute(
        tool_name="sqlmap",
        tag_filters=["sqli", "sql-injection", "sql", "injection"],
        severity_escalation="critical",
    ),
    ToolRoute(
        tool_name="tplmap",
        tag_filters=["ssti", "template-injection", "template"],
        severity_escalation="critical",
    ),
    ToolRoute(
        tool_name="xxeinjector",
        tag_filters=["xxe", "xml", "xml-injection"],
        severity_escalation="critical",
    ),
    ToolRoute(
        tool_name="commix",
        tag_filters=["rce", "cmdi", "command-injection", "os-command"],
        severity_escalation="critical",
    ),
    ToolRoute(
        tool_name="ssrfmap",
        tag_filters=["ssrf", "server-side-request"],
        severity_escalation="high",
    ),
]


def route_finding(title: str, tags_str: str) -> ToolRoute | None:
    """Return the matching :class:`ToolRoute` for a Nuclei finding, or *None*.

    Matching is performed by checking whether any of the route's
    ``tag_filters`` appear in the combined *title* + *tags_str* text
    (case-insensitive).

    Parameters
    ----------
    title:
        The Nuclei finding title (``info.name``).
    tags_str:
        Comma-separated tags string (``info.tags``).
    """
    combined = f"{title} {tags_str}".lower()

    for route in ROUTES:
        for tag in route.tag_filters:
            if tag in combined:
                return route

    return None
