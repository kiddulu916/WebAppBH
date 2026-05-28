"""Bug bounty platform API clients."""
from lib_webbh.platform_api.hackerone import HackerOneClient
from lib_webbh.platform_api.bugcrowd import BugcrowdClient
from lib_webbh.platform_api.intigriti import IntigritiClient
from lib_webbh.platform_api.yeswehack import YesWeHackClient
from lib_webbh.platform_api.engagement_fetcher import (
    search_programs,
    fetch_engagement,
    ProgramCandidate,
    EngagementResult,
    CampaignFormPrefill,
    StageRule,
)

PLATFORM_CLIENTS = {
    "hackerone": HackerOneClient,
    "bugcrowd": BugcrowdClient,
    "intigriti": IntigritiClient,
    "yeswehack": YesWeHackClient,
}

__all__ = [
    "PLATFORM_CLIENTS",
    "HackerOneClient",
    "BugcrowdClient",
    "IntigritiClient",
    "YesWeHackClient",
    "search_programs",
    "fetch_engagement",
    "ProgramCandidate",
    "EngagementResult",
    "CampaignFormPrefill",
    "StageRule",
]
