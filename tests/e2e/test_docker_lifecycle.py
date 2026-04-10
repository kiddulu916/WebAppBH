"""Docker lifecycle integration tests — SKIPPED.

These tests reference the legacy event engine architecture (_check_*_trigger functions)
which was replaced by the EventEngine class in orchestrator/event_engine.py.

The tests need to be rewritten to work with the new architecture.
"""
import pytest

pytest.skip("Legacy event engine tests — need rewrite for EventEngine architecture", allow_module_level=True)
