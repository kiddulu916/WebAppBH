"""Queue depth monitoring for worker auto-scaling."""
from __future__ import annotations
from enum import Enum


class QueueHealth(Enum):
    IDLE = "idle"
    HEALTHY = "healthy"
    PRESSURE = "pressure"
    CRITICAL = "critical"

    @property
    def should_scale_up(self) -> bool:
        return self in (QueueHealth.PRESSURE, QueueHealth.CRITICAL)

    @property
    def should_scale_down(self) -> bool:
        return self == QueueHealth.IDLE


def assess_queue_health(pending: int, threshold: int = 50) -> QueueHealth:
    """Assess queue health based on pending message count.

    Args:
        pending: Number of pending messages in the queue.
        threshold: Base threshold for healthy queue depth.

    Returns:
        QueueHealth enum indicating current queue state.
    """
    if pending == 0:
        return QueueHealth.IDLE
    if pending <= threshold:
        return QueueHealth.HEALTHY
    if pending < threshold * 4:
        return QueueHealth.PRESSURE
    return QueueHealth.CRITICAL
