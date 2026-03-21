"""Asset diff computation for live recon diffing."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class DiffResult:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)


def compute_diff(previous: dict[str, str], current: dict[str, str]) -> DiffResult:
    prev_keys = set(previous.keys())
    curr_keys = set(current.keys())
    added = sorted(curr_keys - prev_keys)
    removed = sorted(prev_keys - curr_keys)
    unchanged = sorted(curr_keys & prev_keys)
    return DiffResult(added=added, removed=removed, unchanged=unchanged)
