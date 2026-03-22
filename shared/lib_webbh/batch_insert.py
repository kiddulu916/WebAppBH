"""Batched async DB inserts with configurable flush interval and size."""
from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy.orm import DeclarativeBase

from lib_webbh.database import get_session


class BatchInserter:
    """Buffer ORM instances and flush in batches.

    Usage:
        inserter = BatchInserter(batch_size=50, flush_interval=2.0)
        await inserter.add(Asset(target_id=1, asset_type="subdomain", asset_value="a.com"))
        await inserter.flush()  # ensure all remaining items are written
    """

    def __init__(self, batch_size: int = 50, flush_interval: float = 2.0):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._buffer: list[Any] = []
        self._lock = asyncio.Lock()
        self._flush_task: asyncio.Task | None = None
        self._total_flushed: int = 0

    async def add(self, instance: Any) -> None:
        """Add an ORM instance to the buffer. Flushes when batch_size is reached."""
        async with self._lock:
            self._buffer.append(instance)
            if len(self._buffer) >= self.batch_size:
                await self._flush_locked()
            elif self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(self._timed_flush())

    async def _timed_flush(self) -> None:
        """Flush after flush_interval seconds if buffer is non-empty."""
        await asyncio.sleep(self.flush_interval)
        async with self._lock:
            if self._buffer:
                await self._flush_locked()

    async def _flush_locked(self) -> None:
        """Flush the buffer. Must be called with _lock held."""
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()
        async with get_session() as session:
            session.add_all(batch)
            await session.commit()
        self._total_flushed += len(batch)

    async def flush(self) -> int:
        """Flush remaining items. Returns total items flushed across all batches."""
        async with self._lock:
            await self._flush_locked()
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        return self._total_flushed

    @property
    def pending(self) -> int:
        """Number of items in the buffer awaiting flush."""
        return len(self._buffer)
