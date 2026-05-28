import pytest


def test_search_programs_importable_from_platform_api():
    from lib_webbh.platform_api import search_programs, fetch_engagement
    from lib_webbh.platform_api import ProgramCandidate, EngagementResult, CampaignFormPrefill, StageRule
    assert callable(search_programs)
    assert callable(fetch_engagement)
    assert callable(ProgramCandidate)
    assert callable(EngagementResult)
    assert callable(CampaignFormPrefill)
    assert callable(StageRule)


def test_dataclasses_importable_from_lib_webbh():
    from lib_webbh import CampaignFormPrefill, EngagementResult, ProgramCandidate, StageRule
    from lib_webbh.platform_api.engagement_fetcher import CampaignFormPrefill as CFP
    assert CampaignFormPrefill is CFP


async def test_search_programs_raises_on_unknown_platform():
    from lib_webbh.platform_api import search_programs
    with pytest.raises(ValueError, match="Unsupported platform"):
        await search_programs("unknown_platform", "Acme")
