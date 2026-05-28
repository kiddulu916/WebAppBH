"""Smoke tests: public entry points importable from the correct paths."""

def test_search_programs_importable_from_platform_api():
    from lib_webbh.platform_api import search_programs, fetch_engagement
    from lib_webbh.platform_api import ProgramCandidate, EngagementResult, CampaignFormPrefill, StageRule
    assert callable(search_programs)
    assert callable(fetch_engagement)


def test_dataclasses_importable_from_lib_webbh():
    from lib_webbh import CampaignFormPrefill, EngagementResult, ProgramCandidate, StageRule
    # Verify they are the same objects (not re-implementations)
    from lib_webbh.platform_api.engagement_fetcher import CampaignFormPrefill as CFP
    assert CampaignFormPrefill is CFP


def test_search_programs_raises_on_unknown_platform():
    import asyncio
    from lib_webbh.platform_api import search_programs
    with pytest.raises(ValueError, match="Unsupported platform"):
        asyncio.run(search_programs("unknown_platform", "Acme"))

import pytest
