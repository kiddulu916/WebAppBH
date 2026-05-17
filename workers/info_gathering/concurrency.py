# workers/info_gathering/concurrency.py
import asyncio
import os

HEAVY_LIMIT = int(os.environ.get("HEAVY_CONCURRENCY", "2"))
LIGHT_LIMIT = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))

TOOL_WEIGHTS = {
    "DorkEngine": "LIGHT",
    "ArchiveProber": "LIGHT",
    "WhatWeb": "LIGHT",
    "Httpx": "LIGHT",
    "LivenessProbe": "LIGHT",
    "BannerProbe": "LIGHT",
    "HeaderOrderProbe": "LIGHT",
    "MethodProbe": "LIGHT",
    "ErrorPageProbe": "LIGHT",
    "TLSProbe": "LIGHT",
    "WAFProbe": "LIGHT",
    "MetafileParser": "LIGHT",
    "MetaTagAnalyzer": "LIGHT",
    "CTLogSearcher": "LIGHT",
    "AppPathEnumerator": "HEAVY",
    "Subfinder": "HEAVY",
    "Assetfinder": "LIGHT",
    "AmassPassive": "HEAVY",
    "AmassActive": "HEAVY",
    "Massdns": "HEAVY",
    "VHostProber": "LIGHT",
    "CommentHarvester": "LIGHT",
    "MetadataExtractor": "LIGHT",
    "JsSecretScanner": "HEAVY",
    "SourceMapProber": "LIGHT",
    "RedirectBodyInspector": "LIGHT",
    "FormMapper": "LIGHT",
    "Paramspider": "LIGHT",
    "WebSocketProber":      "LIGHT",
    "EntryPointAggregator": "LIGHT",
    "Katana": "HEAVY",
    "Hakrawler": "LIGHT",
    "Wappalyzer": "LIGHT",
    "CookieFingerprinter": "LIGHT",
    "Webanalyze": "LIGHT",
    "HeaderFrameworkProbe": "LIGHT",
    "MetaGeneratorProbe":   "LIGHT",
    "FrameworkFileProber":  "LIGHT",
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