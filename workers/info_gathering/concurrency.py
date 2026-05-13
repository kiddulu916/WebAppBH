# workers/info_gathering/concurrency.py
import asyncio
import os

HEAVY_LIMIT = 2
LIGHT_LIMIT = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))

TOOL_WEIGHTS = {
    "DorkEngine": "LIGHT",
    "ArchiveProber": "LIGHT",
    # Nmap moved out of Stage 2 in Phase 3; Stage 9 handles full TCP/UDP discovery.
    "WhatWeb": "LIGHT",
    "Httpx": "LIGHT",
    # Stage 2 (WSTG-INFO-02) probes — all LIGHT (a handful of HTTP requests each).
    "LivenessProbe": "LIGHT",
    "BannerProbe": "LIGHT",
    "HeaderOrderProbe": "LIGHT",
    "MethodProbe": "LIGHT",
    "ErrorPageProbe": "LIGHT",
    "TLSProbe": "LIGHT",
    "WAFProbe": "LIGHT",
    "MetafileParser": "LIGHT",
    "Subfinder": "HEAVY",
    "Assetfinder": "LIGHT",
    "AmassPassive": "HEAVY",
    "AmassActive": "HEAVY",
    "Massdns": "HEAVY",
    "VHostProber": "LIGHT",
    "CommentHarvester": "LIGHT",
    "MetadataExtractor": "LIGHT",
    "FormMapper": "LIGHT",
    "Paramspider": "LIGHT",
    "Katana": "HEAVY",
    "Hakrawler": "LIGHT",
    "Wappalyzer": "LIGHT",
    "CookieFingerprinter": "LIGHT",
    "Webanalyze": "LIGHT",
    "Naabu": "HEAVY",
    "Waybackurls": "LIGHT",
    "ArchitectureModeler": "LIGHT",
    "ApplicationMapper": "LIGHT",
    "AttackSurfaceAnalyzer": "LIGHT",
    "CacheProber": "LIGHT",
    "ShodanSearcher": "LIGHT",
    "CensysSearcher": "LIGHT",
    "SecurityTrailsSearcher": "LIGHT",
}


def get_semaphores() -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
    return asyncio.Semaphore(HEAVY_LIMIT), asyncio.Semaphore(LIGHT_LIMIT)