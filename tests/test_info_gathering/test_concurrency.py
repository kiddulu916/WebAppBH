# tests/test_info_gathering/test_concurrency.py
import asyncio


def test_get_semaphores_returns_bounded_semaphores():
    from workers.info_gathering.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.Semaphore)
    assert isinstance(light, asyncio.Semaphore)


def test_tool_weights_contains_all_tools():
    from workers.info_gathering.concurrency import TOOL_WEIGHTS

    expected_tools = {
        "DorkEngine", "ArchiveProber", "WhatWeb", "Httpx",
        # Stage 2 (WSTG-INFO-02) probes
        "LivenessProbe", "BannerProbe", "HeaderOrderProbe", "MethodProbe",
        "ErrorPageProbe", "TLSProbe", "WAFProbe",
        "MetafileParser", "Subfinder", "Assetfinder", "AmassPassive",
        "AmassActive", "Massdns", "VHostProber", "CommentHarvester",
        "MetadataExtractor", "FormMapper", "Paramspider", "Katana",
        "Hakrawler", "Wappalyzer", "CookieFingerprinter", "Webanalyze",
        "Naabu", "Waybackurls", "ArchitectureModeler",
        "ApplicationMapper", "AttackSurfaceAnalyzer",
        "CacheProber", "ShodanSearcher", "CensysSearcher", "SecurityTrailsSearcher",
    }
    assert set(TOOL_WEIGHTS.keys()) == expected_tools


def test_tool_weights_valid_values():
    from workers.info_gathering.concurrency import TOOL_WEIGHTS

    for tool, weight in TOOL_WEIGHTS.items():
        assert weight in ("HEAVY", "LIGHT"), f"{tool} has invalid weight: {weight}"