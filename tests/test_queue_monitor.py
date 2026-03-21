"""Test queue depth monitoring."""
import pytest
from lib_webbh.queue_monitor import QueueHealth, assess_queue_health

def test_healthy_queue():
    health = assess_queue_health(pending=5, threshold=50)
    assert health == QueueHealth.HEALTHY
    assert health.should_scale_up is False

def test_pressure_queue():
    health = assess_queue_health(pending=60, threshold=50)
    assert health == QueueHealth.PRESSURE
    assert health.should_scale_up is True

def test_critical_queue():
    health = assess_queue_health(pending=200, threshold=50)
    assert health == QueueHealth.CRITICAL
    assert health.should_scale_up is True

def test_empty_queue():
    health = assess_queue_health(pending=0, threshold=50)
    assert health == QueueHealth.IDLE
    assert health.should_scale_down is True
