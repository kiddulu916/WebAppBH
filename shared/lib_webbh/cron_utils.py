"""Cron expression utilities using croniter."""
from __future__ import annotations

from datetime import datetime, timezone

from croniter import croniter


def next_run(cron_expression: str, now: datetime | None = None) -> datetime:
    """Calculate the next run time from a cron expression.

    Returns a naive datetime (UTC) to match the TIMESTAMP WITHOUT TIME ZONE
    columns used in the database.
    """
    now = now or datetime.now(timezone.utc)
    nxt = croniter(cron_expression, now).get_next(datetime)
    # Strip tzinfo so asyncpg accepts it for tz-naive TIMESTAMP columns
    return nxt.replace(tzinfo=None) if nxt.tzinfo else nxt


def is_valid_cron(expression: str) -> bool:
    """Check if a cron expression is valid."""
    try:
        croniter(expression)
        return True
    except (ValueError, KeyError):
        return False
