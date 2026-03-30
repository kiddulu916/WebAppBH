# orchestrator/resource_guard.py
import os
from typing import Optional


class ResourceGuard:
    """Monitors system resources and controls processing throughput."""

    THRESHOLDS = {
        "green":  {
            "cpu": int(os.environ.get("RESOURCE_GUARD_CPU_GREEN", "60")),
            "memory": int(os.environ.get("RESOURCE_GUARD_MEM_GREEN", "60")),
            "workers": int(os.environ.get("RESOURCE_GUARD_WORKERS_GREEN", "8")),
        },
        "yellow": {
            "cpu": int(os.environ.get("RESOURCE_GUARD_CPU_YELLOW", "80")),
            "memory": int(os.environ.get("RESOURCE_GUARD_MEM_YELLOW", "80")),
            "workers": int(os.environ.get("RESOURCE_GUARD_WORKERS_YELLOW", "12")),
        },
        "red": {
            "cpu": int(os.environ.get("RESOURCE_GUARD_CPU_RED", "90")),
            "memory": int(os.environ.get("RESOURCE_GUARD_MEM_RED", "90")),
            "workers": int(os.environ.get("RESOURCE_GUARD_WORKERS_RED", "16")),
        },
    }

    def __init__(self):
        self._override: Optional[str] = None

    def set_override(self, tier: str):
        self._override = tier

    def clear_override(self):
        self._override = None

    async def get_current_tier(self) -> str:
        if self._override:
            return self._override

        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory().percent
        except ImportError:
            cpu = 0
            memory = 0

        active_workers = await self._count_active_workers()

        if (cpu > self.THRESHOLDS["red"]["cpu"] or
            memory > self.THRESHOLDS["red"]["memory"] or
            active_workers > self.THRESHOLDS["red"]["workers"]):
            return "critical"
        elif (cpu > self.THRESHOLDS["yellow"]["cpu"] or
              memory > self.THRESHOLDS["yellow"]["memory"] or
              active_workers > self.THRESHOLDS["yellow"]["workers"]):
            return "red"
        elif (cpu > self.THRESHOLDS["green"]["cpu"] or
              memory > self.THRESHOLDS["green"]["memory"] or
              active_workers > self.THRESHOLDS["green"]["workers"]):
            return "yellow"
        else:
            return "green"

    def get_batch_config(self, tier: str) -> dict:
        configs = {
            "green": {
                "queues": ["critical", "high", "normal", "low"],
                "batch_multiplier": 1.0,
                "delay_seconds": 0,
            },
            "yellow": {
                "queues": ["critical", "high", "normal"],
                "batch_multiplier": 0.5,
                "delay_seconds": 1,
            },
            "red": {
                "queues": ["critical", "high"],
                "batch_multiplier": 0.25,
                "delay_seconds": 5,
            },
            "critical": {
                "queues": [],
                "batch_multiplier": 0,
                "delay_seconds": 10,
            },
        }
        return configs[tier]

    async def _count_active_workers(self) -> int:
        from lib_webbh.database import get_session, JobState
        from sqlalchemy import select, func

        try:
            async with get_session() as session:
                result = await session.execute(
                    select(func.count(JobState.id))
                    .where(JobState.status == "running")
                )
                return result.scalar() or 0
        except Exception:
            return 0