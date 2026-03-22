"""Cron expression utilities using croniter."""
from __future__ import annotations

from datetime import datetime, timezone

from croniter import croniter


def next_run(cron_expression: str, now: datetime | None = None) -> datetime:
    """Calculate the next run time from a cron expression."""
    now = now or datetime.now(timezone.utc)
    return croniter(cron_expression, now).get_next(datetime)


def is_valid_cron(expression: str) -> bool:
    """Check if a cron expression is valid."""
    try:
        croniter(expression)
        return True
    except (ValueError, KeyError):
        return False
