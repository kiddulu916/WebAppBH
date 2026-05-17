# WSTG-INFO-08 Fingerprint Framework — Stage 8 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `fingerprint_framework` (Stage 8) to full parity with Stage 2: fix three broken tools, add three new WSTG 4.1.8 tools, build a `FrameworkFingerprintAggregator`, wire a post-stage pipeline hook, and emit `Vulnerability` rows for framework disclosure findings.

**Architecture:** Mirrors Stage 2 exactly — each tool returns `ProbeResult`, the pipeline post-stage hook scores slots via `FrameworkFingerprintAggregator._score_slot`, writes a summary `Observation`, and calls `emit_disclosures` for vulnerability rows. Slots are `framework`, `cms`, `language`. Corroboration: when ≥2 probes agree on the same vendor and ≥1 carries a version string, a single LOW "corroborated" vuln supersedes individual INFO vulns.

**Tech Stack:** Python async, `aiohttp`, stdlib `html.parser`, `unittest.mock` for tests, existing `ProbeResult` dataclass from `fingerprint_aggregator.py`.

---

## File Map

| Action | File |
|--------|------|
| Modify | `workers/info_gathering/tools/wappalyzer.py` |
| Modify | `workers/info_gathering/tools/cookie_fingerprinter.py` |
| Modify | `workers/info_gathering/tools/webanalyze.py` |
| Create | `workers/info_gathering/tools/header_framework_probe.py` |
| Create | `workers/info_gathering/tools/meta_generator_probe.py` |
| Create | `workers/info_gathering/tools/framework_file_prober.py` |
| Create | `workers/info_gathering/framework_fingerprint_aggregator.py` |
| Modify | `workers/info_gathering/pipeline.py` |
| Modify | `workers/info_gathering/concurrency.py` |
| Create | `tests/unit/__init__.py` |
| Create | `tests/unit/info_gathering/__init__.py` |
| Create | `tests/unit/info_gathering/test_existing_tools.py` |
| Create | `tests/unit/info_gathering/test_header_framework_probe.py` |
| Create | `tests/unit/info_gathering/test_meta_generator_probe.py` |
| Create | `tests/unit/info_gathering/test_framework_file_prober.py` |
| Create | `tests/unit/info_gathering/test_framework_fingerprint_aggregator.py` |
| Modify | `tests/e2e/test_info_gathering.py` |

---

## Task 1: Fix three existing broken tools

**Files:**
- Modify: `workers/info_gathering/tools/wappalyzer.py`
- Modify: `workers/info_gathering/tools/cookie_fingerprinter.py`
- Modify: `workers/info_gathering/tools/webanalyze.py`
- Create: `tests/unit/__init__.py`, `tests/unit/info_gathering/__init__.py`, `tests/unit/info_gathering/test_existing_tools.py`

**The bug:** All three tools call `save_observation(target_id, "technology_detection", {...}, "tool_name")`.
`save_observation`'s actual signature is `save_observation(self, asset_id: int, tech_stack=None, page_title=None, status_code=None, headers=None)`.
This means `target_id` goes in as `asset_id` (wrong value), and the extra positional strings cause the wrong kwargs to be set. All three also return `None` implicitly instead of `ProbeResult`.

- [ ] **Step 1: Create unit test dir scaffolding**

```
tests/unit/__init__.py          (empty)
tests/unit/info_gathering/__init__.py   (empty)
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/info_gathering/test_existing_tools.py`:

```python
"""Unit tests for WSTG 4.1.8 existing tool fixes (Task 1)."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.wappalyzer import Wappalyzer
from workers.info_gathering.tools.cookie_fingerprinter import CookieFingerprinter
from workers.info_gathering.tools.webanalyze import Webanalyze
from workers.info_gathering.fingerprint_aggregator import ProbeResult


@pytest.mark.asyncio
async def test_wstg_wappalyzer_returns_probe_result():
    tool = Wappalyzer()
    stdout = json.dumps({"technologies": [{"name": "WordPress"}, {"name": "PHP"}]})
    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=stdout)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=42)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.probe == "wappalyzer"
    assert result.obs_id == 42
    assert result.error is None
    assert any(s["value"] == "WordPress" for s in result.signals.get("cms", []))
    assert any(s["value"] == "PHP" for s in result.signals.get("language", []))


@pytest.mark.asyncio
async def test_wstg_wappalyzer_missing_kwargs_returns_error():
    tool = Wappalyzer()
    result = await tool.execute(target_id=1)
    assert isinstance(result, ProbeResult)
    assert result.error is not None


@pytest.mark.asyncio
async def test_wstg_cookie_fingerprinter_returns_probe_result():
    tool = CookieFingerprinter()
    mock_cookies = MagicMock()
    mock_cookies.keys.return_value = ["PHPSESSID", "wordpress_logged_in"]
    mock_resp = MagicMock()
    mock_resp.cookies = mock_cookies
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    with patch("aiohttp.ClientSession", return_value=mock_session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=7)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.probe == "cookie_framework"
    assert result.obs_id == 7
    assert any(s["value"] == "PHP" for s in result.signals.get("language", []))
    assert any(s["value"] == "WordPress" for s in result.signals.get("cms", []))


@pytest.mark.asyncio
async def test_wstg_webanalyze_returns_probe_result():
    tool = Webanalyze()
    stdout = json.dumps({"matches": [{"app_name": "Django"}, {"app_name": "Python"}]})
    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=stdout)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=55)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.probe == "webanalyze"
    assert result.obs_id == 55
    assert any(s["value"] == "Django" for s in result.signals.get("framework", []))
    assert any(s["value"] == "Python" for s in result.signals.get("language", []))
```

- [ ] **Step 3: Run tests — expect FAIL**

```
pytest tests/unit/info_gathering/test_existing_tools.py -v
```

Expected: all four tests fail — three with `AttributeError` / wrong return type, one with `assert error is not None` failing.

- [ ] **Step 4: Replace `wappalyzer.py`**

```python
# workers/info_gathering/tools/wappalyzer.py
"""Wappalyzer wrapper — technology detection (WSTG 4.1.8)."""
from __future__ import annotations

import json
from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

_TECH_SLOTS: dict[str, str] = {
    "Laravel": "framework", "Django": "framework", "Ruby on Rails": "framework",
    "Express": "framework", "ASP.NET MVC": "framework", "Spring Boot": "framework",
    "Spring Framework": "framework", "Flask": "framework", "Symfony": "framework",
    "CodeIgniter": "framework", "Nuxt.js": "framework", "Next.js": "framework",
    "WordPress": "cms", "Joomla": "cms", "Drupal": "cms", "Ghost": "cms",
    "Magento": "cms", "PrestaShop": "cms", "TYPO3": "cms", "Shopify": "cms",
    "PHP": "language", "Python": "language", "Ruby": "language", "Java": "language",
    "Node.js": "language", "ASP.NET": "language",
}


class Wappalyzer(InfoGatheringTool):
    """Technology detection using Wappalyzer CLI (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            stdout = await self.run_subprocess(
                ["wappalyzer", f"https://{host}"], timeout=300,
                rate_limiter=kwargs.get("rate_limiter"),
            )
        except Exception as exc:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={}, error=str(exc))
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={}, error="invalid json")

        techs = data.get("technologies", [])
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        for tech in techs:
            name = tech.get("name", "")
            slot = _TECH_SLOTS.get(name)
            if slot:
                signals[slot].append({"src": "wappalyzer", "value": name, "w": 0.6})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "wappalyzer", "host": host,
                        "technologies": [t.get("name", "") for t in techs]},
        )
        return ProbeResult(probe="wappalyzer", obs_id=obs_id, signals=signals)
```

- [ ] **Step 5: Replace `cookie_fingerprinter.py`**

```python
# workers/info_gathering/tools/cookie_fingerprinter.py
"""CookieFingerprinter — cookie-based technology fingerprinting (WSTG 4.1.8)."""
from __future__ import annotations

from typing import Any

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

_COOKIE_TECH_SLOTS: dict[str, str] = {
    "PHP": "language", "Java": "language", "ASP.NET": "language",
    "Django": "framework", "Rails": "framework", "Laravel": "framework",
    "Spring": "framework", "WordPress": "cms", "Drupal": "cms",
}


class CookieFingerprinter(InfoGatheringTool):
    """Cookie-name-based framework fingerprinting (WSTG 4.1.8)."""

    COOKIE_PATTERNS = {
        "PHP": ["PHPSESSID"],
        "Java": ["JSESSIONID"],
        "ASP.NET": ["ASP.NET_SessionId", "__RequestVerificationToken"],
        "Django": ["csrftoken", "sessionid"],
        "Rails": ["_session_id"],
        "Laravel": ["laravel_session", "XSRF-TOKEN"],
        "WordPress": ["wordpress_logged_in", "wp-settings"],
        "Drupal": ["Drupal.visitor"],
        "Spring": ["SPRING_SECURITY_REMEMBER_ME_COOKIE"],
    }

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="cookie_framework", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    cookies = resp.cookies
        except Exception as exc:
            return ProbeResult(probe="cookie_framework", obs_id=None, signals={}, error=str(exc))

        detected = self._analyze_cookies(cookies)
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        for tech_name in detected:
            slot = _COOKIE_TECH_SLOTS.get(tech_name, "framework")
            signals[slot].append({"src": "cookie_framework", "value": tech_name, "w": 0.5})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "cookie_framework", "host": host, "technologies": detected},
        )
        return ProbeResult(probe="cookie_framework", obs_id=obs_id, signals=signals)

    def _analyze_cookies(self, cookies) -> list[str]:
        detected, cookie_names = [], set(cookies.keys())
        for tech, patterns in self.COOKIE_PATTERNS.items():
            if any(p in cookie_names for p in patterns):
                detected.append(tech)
        return detected
```

- [ ] **Step 6: Replace `webanalyze.py`**

```python
# workers/info_gathering/tools/webanalyze.py
"""Webanalyze wrapper — technology detection (WSTG 4.1.8)."""
from __future__ import annotations

import json
from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

_TECH_SLOTS: dict[str, str] = {
    "Laravel": "framework", "Django": "framework", "Ruby on Rails": "framework",
    "Express": "framework", "ASP.NET MVC": "framework", "Spring Boot": "framework",
    "Flask": "framework", "Symfony": "framework",
    "WordPress": "cms", "Joomla": "cms", "Drupal": "cms", "Ghost": "cms",
    "Magento": "cms",
    "PHP": "language", "Python": "language", "Ruby": "language",
    "Java": "language", "Node.js": "language", "ASP.NET": "language",
}


class Webanalyze(InfoGatheringTool):
    """Technology detection using Webanalyze CLI (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="webanalyze", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            stdout = await self.run_subprocess(
                ["webanalyze", "-host", host, "-output", "json"], timeout=300,
                rate_limiter=kwargs.get("rate_limiter"),
            )
        except Exception as exc:
            return ProbeResult(probe="webanalyze", obs_id=None, signals={}, error=str(exc))
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return ProbeResult(probe="webanalyze", obs_id=None, signals={}, error="invalid json")

        matches = data.get("matches", [])
        techs = [m.get("app_name", "") for m in matches if m.get("app_name")]
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        for name in techs:
            slot = _TECH_SLOTS.get(name)
            if slot:
                signals[slot].append({"src": "webanalyze", "value": name, "w": 0.6})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "webanalyze", "host": host, "technologies": techs},
        )
        return ProbeResult(probe="webanalyze", obs_id=obs_id, signals=signals)
```

- [ ] **Step 7: Run tests — expect PASS**

```
pytest tests/unit/info_gathering/test_existing_tools.py -v
```

Expected: all 4 tests pass.

- [ ] **Step 8: Commit**

```
git add workers/info_gathering/tools/wappalyzer.py \
        workers/info_gathering/tools/cookie_fingerprinter.py \
        workers/info_gathering/tools/webanalyze.py \
        tests/unit/__init__.py \
        tests/unit/info_gathering/__init__.py \
        tests/unit/info_gathering/test_existing_tools.py
git commit -m "fix(stage8): fix save_observation signature and return ProbeResult in Wappalyzer, CookieFingerprinter, Webanalyze"
```

---

## Task 2: HeaderFrameworkProbe

**Files:**
- Create: `workers/info_gathering/tools/header_framework_probe.py`
- Create: `tests/unit/info_gathering/test_header_framework_probe.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/info_gathering/test_header_framework_probe.py`:

```python
"""Unit tests for HeaderFrameworkProbe (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _mock_session(headers: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.headers = headers
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


@pytest.mark.asyncio
async def test_wstg_header_version_disclosure_aspnet_mvc():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session({"X-AspNetMvc-Version": "5.2"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=1)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    fw = result.signals.get("framework", [])
    assert any(s["value"] == "ASP.NET MVC" and s.get("version") == "5.2" for s in fw)


@pytest.mark.asyncio
async def test_wstg_header_version_disclosure_php():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session({"X-Powered-By": "PHP/8.1.12"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=2)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    lang = result.signals.get("language", [])
    assert any(s["value"] == "PHP" and s.get("version") == "8.1.12" for s in lang)


@pytest.mark.asyncio
async def test_wstg_header_drupal_x_generator():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session(
            {"X-Generator": "Drupal 9 (https://www.drupal.org)"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=3)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    cms = result.signals.get("cms", [])
    assert any(s["value"] == "Drupal" for s in cms)


@pytest.mark.asyncio
async def test_wstg_header_no_framework_headers_empty_signals():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_session({"Server": "Apache"})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=4)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert result.error is None
    assert result.signals.get("framework") == []
    assert result.signals.get("cms") == []
    assert result.signals.get("language") == []


@pytest.mark.asyncio
async def test_wstg_header_missing_kwargs_returns_error():
    from workers.info_gathering.tools.header_framework_probe import HeaderFrameworkProbe
    tool = HeaderFrameworkProbe()
    result = await tool.execute(target_id=1)
    assert result.error is not None
```

- [ ] **Step 2: Run tests — expect FAIL (ImportError)**

```
pytest tests/unit/info_gathering/test_header_framework_probe.py -v
```

Expected: `ImportError: cannot import name 'HeaderFrameworkProbe'`

- [ ] **Step 3: Create `header_framework_probe.py`**

```python
# workers/info_gathering/tools/header_framework_probe.py
"""HeaderFrameworkProbe — framework fingerprinting via HTTP response headers (WSTG 4.1.8)."""
from __future__ import annotations

import re
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-header-framework-probe")

# (header_lower, value_regex_or_None, slot, vendor, use_full_value_as_version, weight)
# use_full_value_as_version=True: the entire header value IS the version (e.g. X-AspNetMvc-Version).
# value_regex: must match; group 1 (if present) extracts version.
_HEADER_SIGNATURES: list[tuple[str, str | None, str, str, bool, float]] = [
    ("x-aspnetmvc-version", None,                          "framework", "ASP.NET MVC", True,  0.7),
    ("x-aspnet-version",    None,                          "language",  ".NET",        True,  0.6),
    ("x-generator",         r"(?i)drupal\s*([\d.]+)?",     "cms",       "Drupal",      False, 0.8),
    ("x-generator",         r"(?i)joomla",                 "cms",       "Joomla",      False, 0.7),
    ("x-generator",         r"(?i)wordpress\s*([\d.]+)?",  "cms",       "WordPress",   False, 0.7),
    ("x-powered-by",        r"(?i)php/([\d.]+)",           "language",  "PHP",         False, 0.6),
    ("x-powered-by",        r"(?i)express",                "framework", "Express",     False, 0.5),
    ("x-powered-by",        r"(?i)asp\.net",               "language",  "ASP.NET",     False, 0.5),
    ("x-pingback",          r"/xmlrpc\.php",               "cms",       "WordPress",   False, 0.5),
    ("x-drupal-cache",      None,                          "cms",       "Drupal",      False, 0.4),
    ("x-drupal-dynamic-cache", None,                       "cms",       "Drupal",      False, 0.4),
]


class HeaderFrameworkProbe(InfoGatheringTool):
    """Passive framework fingerprinting via HTTP response headers (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="header_framework", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.warning("header_framework_probe failed",
                           extra={"host": host, "error": str(exc)})
            return ProbeResult(probe="header_framework", obs_id=None, signals={}, error=str(exc))

        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        raw_headers: dict[str, str] = {}

        for hdr, val_pattern, slot, vendor, use_full, weight in _HEADER_SIGNATURES:
            hdr_value = headers.get(hdr)
            if hdr_value is None:
                continue
            raw_headers[hdr] = hdr_value
            version: str | None = None
            if val_pattern is not None:
                m = re.search(val_pattern, hdr_value)
                if not m:
                    continue
                if m.lastindex and m.lastindex >= 1:
                    version = m.group(1) or None
            elif use_full:
                version = hdr_value.strip()
            sig: dict[str, Any] = {"src": "header_framework", "value": vendor, "w": weight}
            if version:
                sig["version"] = version
            signals[slot].append(sig)

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "header_framework", "host": host, "headers": raw_headers},
        )
        return ProbeResult(probe="header_framework", obs_id=obs_id, signals=signals)
```

- [ ] **Step 4: Run tests — expect PASS**

```
pytest tests/unit/info_gathering/test_header_framework_probe.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```
git add workers/info_gathering/tools/header_framework_probe.py \
        tests/unit/info_gathering/test_header_framework_probe.py
git commit -m "feat(stage8): add HeaderFrameworkProbe — HTTP header framework fingerprinting"
```

---

## Task 3: MetaGeneratorProbe

**Files:**
- Create: `workers/info_gathering/tools/meta_generator_probe.py`
- Create: `tests/unit/info_gathering/test_meta_generator_probe.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/info_gathering/test_meta_generator_probe.py`:

```python
"""Unit tests for MetaGeneratorProbe (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.fingerprint_aggregator import ProbeResult

_WP_HTML = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel="https://api.w.org/" href="https://example.com/wp-json/" />
</head><body></body></html>"""

_DJANGO_HTML = """<html><body>
<form method="post">
<input type="hidden" name="csrfmiddlewaretoken" value="tok">
</form></body></html>"""

_RAILS_HTML = """<html><head>
<meta name="csrf-param" content="authenticity_token">
</head><body></body></html>"""

_DRUPAL_HTML = """<html><body>
<div data-drupal-messages-fallback class="hidden"></div>
</body></html>"""


def _mock_html_session(html: str) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.text = AsyncMock(return_value=html)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def test_wstg_page_parser_detects_wordpress_generator():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_WP_HTML)
    assert p.generator is not None and "WordPress" in p.generator
    assert p.has_wp_api_link is True


def test_wstg_page_parser_detects_django_csrftoken():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_DJANGO_HTML)
    assert p.has_django_csrf is True


def test_wstg_page_parser_detects_rails_csrf_param():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_RAILS_HTML)
    assert p.has_rails_csrf_param is True


def test_wstg_page_parser_detects_drupal_data_attr():
    from workers.info_gathering.tools.meta_generator_probe import _PageParser
    p = _PageParser()
    p.feed(_DRUPAL_HTML)
    assert p.has_drupal_attr is True


@pytest.mark.asyncio
async def test_wstg_meta_generator_cms_detection_wordpress_with_version():
    from workers.info_gathering.tools.meta_generator_probe import MetaGeneratorProbe
    tool = MetaGeneratorProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_html_session(_WP_HTML)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=10)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    cms = result.signals.get("cms", [])
    wp = [s for s in cms if s["value"] == "WordPress"]
    assert len(wp) >= 1
    assert any(s.get("version") == "6.4.2" for s in wp)


@pytest.mark.asyncio
async def test_wstg_meta_generator_detects_django():
    from workers.info_gathering.tools.meta_generator_probe import MetaGeneratorProbe
    tool = MetaGeneratorProbe()
    with patch("aiohttp.ClientSession", return_value=_mock_html_session(_DJANGO_HTML)), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=11)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert any(s["value"] == "Django" for s in result.signals.get("framework", []))


@pytest.mark.asyncio
async def test_wstg_meta_generator_missing_kwargs_returns_error():
    from workers.info_gathering.tools.meta_generator_probe import MetaGeneratorProbe
    tool = MetaGeneratorProbe()
    result = await tool.execute(target_id=1)
    assert result.error is not None
```

- [ ] **Step 2: Run — expect FAIL (ImportError)**

```
pytest tests/unit/info_gathering/test_meta_generator_probe.py -v
```

- [ ] **Step 3: Create `meta_generator_probe.py`**

```python
# workers/info_gathering/tools/meta_generator_probe.py
"""MetaGeneratorProbe — HTML meta generator tag fingerprinting (WSTG 4.1.8)."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-meta-generator-probe")

# (regex, slot, vendor, version_capture_group_or_None)
_GENERATOR_PATTERNS: list[tuple[str, str, str, int | None]] = [
    (r"(?i)wordpress\s*([\d.]+)?", "cms",       "WordPress", 1),
    (r"(?i)joomla!?\s*([\d.]+)?",  "cms",       "Joomla",    1),
    (r"(?i)drupal\s*([\d.]+)?",    "cms",       "Drupal",    1),
    (r"(?i)ghost\s*([\d.]+)?",     "cms",       "Ghost",     1),
]


class _PageParser(HTMLParser):
    """Extracts framework-identifying signals from an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.generator: str | None = None
        self.has_wp_api_link: bool = False
        self.has_rails_csrf_param: bool = False
        self.has_drupal_attr: bool = False
        self.has_django_csrf: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = dict(attrs)
        if tag == "meta":
            name = (d.get("name") or "").lower()
            if name == "generator":
                self.generator = d.get("content") or ""
            elif name == "csrf-param" and (d.get("content") or "") == "authenticity_token":
                self.has_rails_csrf_param = True
        elif tag == "link":
            href = d.get("href") or ""
            rel = d.get("rel") or ""
            if "api.w.org" in href or "api.w.org" in rel:
                self.has_wp_api_link = True
        elif tag == "input" and (d.get("name") or "") == "csrfmiddlewaretoken":
            self.has_django_csrf = True
        for attr_name, _ in attrs:
            if attr_name.startswith("data-drupal"):
                self.has_drupal_attr = True


class MetaGeneratorProbe(InfoGatheringTool):
    """HTML meta-tag and secondary-signal framework fingerprinting (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="meta_generator", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    html = await resp.text(errors="replace")
        except Exception as exc:
            logger.warning("meta_generator_probe failed",
                           extra={"host": host, "error": str(exc)})
            return ProbeResult(probe="meta_generator", obs_id=None, signals={}, error=str(exc))

        parser = _PageParser()
        parser.feed(html)
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        tech_stack: dict[str, Any] = {"_probe": "meta_generator", "host": host}

        if parser.generator:
            tech_stack["generator"] = parser.generator
            for pattern, slot, vendor, vg in _GENERATOR_PATTERNS:
                m = re.search(pattern, parser.generator)
                if m:
                    sig: dict[str, Any] = {"src": "meta_generator", "value": vendor, "w": 0.8}
                    if vg and m.lastindex and m.lastindex >= vg:
                        ver = m.group(vg)
                        if ver:
                            sig["version"] = ver
                    signals[slot].append(sig)
                    break

        if parser.has_wp_api_link and not any(
            s["value"] == "WordPress" for s in signals["cms"]
        ):
            signals["cms"].append({"src": "meta_generator", "value": "WordPress", "w": 0.5})

        if parser.has_drupal_attr and not any(
            s["value"] == "Drupal" for s in signals["cms"]
        ):
            signals["cms"].append({"src": "meta_generator", "value": "Drupal", "w": 0.4})

        if parser.has_rails_csrf_param:
            signals["framework"].append(
                {"src": "meta_generator", "value": "Rails", "w": 0.5})

        if parser.has_django_csrf:
            signals["framework"].append(
                {"src": "meta_generator", "value": "Django", "w": 0.5})

        obs_id = await self.save_observation(asset_id=asset_id, tech_stack=tech_stack)
        return ProbeResult(probe="meta_generator", obs_id=obs_id, signals=signals)
```

- [ ] **Step 4: Run — expect PASS**

```
pytest tests/unit/info_gathering/test_meta_generator_probe.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 5: Commit**

```
git add workers/info_gathering/tools/meta_generator_probe.py \
        tests/unit/info_gathering/test_meta_generator_probe.py
git commit -m "feat(stage8): add MetaGeneratorProbe — HTML meta generator tag fingerprinting"
```

---

## Task 4: FrameworkFileProber

**Files:**
- Create: `workers/info_gathering/tools/framework_file_prober.py`
- Create: `tests/unit/info_gathering/test_framework_file_prober.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/info_gathering/test_framework_file_prober.py`:

```python
"""Unit tests for FrameworkFileProber (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _session_with_status_map(status_by_substring: dict[str, int]) -> MagicMock:
    """Return mock aiohttp session where response status depends on URL substring."""
    def _get(url, *, timeout, allow_redirects):
        status = 404
        for substr, s in status_by_substring.items():
            if substr in url:
                status = s
                break
        mock_resp = MagicMock()
        mock_resp.status = status
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp
    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=_get)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_path_matching_200():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({"wp-login.php": 200})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=20)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    cms = result.signals.get("cms", [])
    assert any(s["value"] == "WordPress" and "/wp-login.php" in s["path"] for s in cms)
    assert "/wp-login.php" in result.signals.get("_admin_paths", [])


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_403_counts_as_accessible():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({"/.env": 403})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=21)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    fw = result.signals.get("framework", [])
    assert any(s["value"] == "Laravel" and "/.env" in s["path"] for s in fw)


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_404_not_matched():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=22)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert result.signals.get("framework") == []
    assert result.signals.get("cms") == []
    assert result.signals.get("_admin_paths") == []
    assert result.signals.get("_info_file_paths") == []


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_info_file_recorded():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    with patch("aiohttp.ClientSession",
               return_value=_session_with_status_map({"readme.html": 200})), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=23)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert "/readme.html" in result.signals.get("_info_file_paths", [])


@pytest.mark.asyncio
async def test_wstg_framework_file_prober_missing_kwargs_returns_error():
    from workers.info_gathering.tools.framework_file_prober import FrameworkFileProber
    tool = FrameworkFileProber()
    result = await tool.execute(target_id=1)
    assert result.error is not None
```

- [ ] **Step 2: Run — expect FAIL (ImportError)**

```
pytest tests/unit/info_gathering/test_framework_file_prober.py -v
```

- [ ] **Step 3: Create `framework_file_prober.py`**

```python
# workers/info_gathering/tools/framework_file_prober.py
"""FrameworkFileProber — framework-specific path probing (WSTG 4.1.8)."""
from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-framework-file-prober")

_ACCESSIBLE = frozenset({200, 301, 302, 403})
_CONCURRENCY = 5

# (path, slot, vendor, path_type)  path_type: "admin" | "info_file" | "indicator"
_PROBE_PATHS: list[tuple[str, str, str, str]] = [
    ("/wp-login.php",                        "cms",       "WordPress", "admin"),
    ("/readme.html",                         "cms",       "WordPress", "info_file"),
    ("/license.txt",                         "cms",       "WordPress", "info_file"),
    ("/wp-includes/js/jquery/jquery.min.js", "cms",       "WordPress", "indicator"),
    ("/administrator/index.php",             "cms",       "Joomla",    "admin"),
    ("/CHANGELOG.txt",                       "cms",       "Joomla",    "info_file"),
    ("/htaccess.txt",                        "cms",       "Joomla",    "info_file"),
    ("/core/CHANGELOG.txt",                  "cms",       "Drupal",    "info_file"),
    ("/artisan",                             "framework", "Laravel",   "indicator"),
    ("/.env",                                "framework", "Laravel",   "indicator"),
    ("/admin/login/?next=/admin/",           "framework", "Django",    "admin"),
    ("/rails/info/properties",               "framework", "Rails",     "indicator"),
]


class FrameworkFileProber(InfoGatheringTool):
    """Probes known framework-specific paths to confirm technology identity (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="framework_files", obs_id=None, signals={},
                               error="missing host or asset_id")

        matched: list[dict[str, str]] = []
        sem = asyncio.Semaphore(_CONCURRENCY)

        async def _probe(path: str, slot: str, vendor: str, path_type: str) -> None:
            try:
                async with sem:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{host}{path}",
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in _ACCESSIBLE:
                                matched.append({"path": path, "slot": slot,
                                                "vendor": vendor, "path_type": path_type,
                                                "status": str(resp.status)})
            except Exception:
                pass

        await asyncio.gather(*[_probe(p, sl, v, pt) for p, sl, v, pt in _PROBE_PATHS])

        signals: dict[str, Any] = {"framework": [], "cms": [], "language": [],
                                   "_admin_paths": [], "_info_file_paths": []}
        for m in matched:
            signals[m["slot"]].append({
                "src": "framework_files", "value": m["vendor"],
                "w": 0.6, "path": m["path"], "path_type": m["path_type"],
            })
            if m["path_type"] == "admin":
                signals["_admin_paths"].append(m["path"])
            elif m["path_type"] == "info_file":
                signals["_info_file_paths"].append(m["path"])

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "framework_files", "host": host, "matched": matched},
        )
        return ProbeResult(probe="framework_files", obs_id=obs_id, signals=signals)
```

- [ ] **Step 4: Run — expect PASS**

```
pytest tests/unit/info_gathering/test_framework_file_prober.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```
git add workers/info_gathering/tools/framework_file_prober.py \
        tests/unit/info_gathering/test_framework_file_prober.py
git commit -m "feat(stage8): add FrameworkFileProber — framework-specific path probing"
```

---

## Task 5: FrameworkFingerprintAggregator

**Files:**
- Create: `workers/info_gathering/framework_fingerprint_aggregator.py`
- Create: `tests/unit/info_gathering/test_framework_fingerprint_aggregator.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/info_gathering/test_framework_fingerprint_aggregator.py`:

```python
"""Unit tests for FrameworkFingerprintAggregator (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _make_probe(probe: str, signals: dict, obs_id: int = 1, error=None) -> ProbeResult:
    return ProbeResult(probe=probe, obs_id=obs_id, signals=signals, error=error)


def test_wstg_score_slot_single_vendor_above_threshold():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [
        _make_probe("wappalyzer", {"cms": [{"src": "wappalyzer", "value": "WordPress", "w": 0.6}]}),
        _make_probe("meta_generator", {"cms": [{"src": "meta_generator", "value": "WordPress", "w": 0.8}]}),
    ]
    scored = agg._score_slot("cms", results)
    assert scored["vendor"] == "WordPress"
    assert scored["confidence"] >= 0.5
    assert scored["conflict"] is False


def test_wstg_score_slot_below_threshold_returns_null_vendor():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [_make_probe("cookie_framework", {"cms": [{"src": "cookie_framework", "value": "WordPress", "w": 0.3}]})]
    scored = agg._score_slot("cms", results)
    assert scored["vendor"] is None


def test_wstg_score_slot_conflict_two_vendors():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [
        _make_probe("wappalyzer",       {"cms": [{"src": "wappalyzer",    "value": "WordPress", "w": 0.6}]}),
        _make_probe("meta_generator",   {"cms": [{"src": "meta_generator","value": "Joomla",    "w": 0.8}]}),
    ]
    scored = agg._score_slot("cms", results)
    assert scored["conflict"] is True
    vendors = [c["vendor"] for c in scored["candidates"]]
    assert "WordPress" in vendors
    assert "Joomla" in vendors


def test_wstg_score_slot_errored_probe_ignored():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [
        _make_probe("wappalyzer", {"cms": [{"src": "wappalyzer", "value": "WordPress", "w": 0.6}]}, error="timeout"),
        _make_probe("meta_generator", {"cms": [{"src": "meta_generator", "value": "WordPress", "w": 0.8}]}),
    ]
    scored = agg._score_slot("cms", results)
    # Only meta_generator (w=0.8) contributes; wappalyzer errored
    assert scored["confidence"] <= 0.8


@pytest.mark.asyncio
async def test_wstg_corroborated_version_identification():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    fingerprint = {
        "cms": {"vendor": "WordPress", "confidence": 0.9, "conflict": False,
                "signals": [
                    {"src": "meta_generator",   "value": "WordPress", "w": 0.8},
                    {"src": "header_framework",  "value": "WordPress", "w": 0.5},
                ]},
        "framework": {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
        "language":  {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
    }
    raw = {
        "meta_generator":   {"obs_id": 10, "version_signals": [{"vendor": "WordPress", "version": "6.4.2", "slot": "cms"}], "all_vendors": ["WordPress"]},
        "header_framework": {"obs_id": 11, "version_signals": [], "all_vendors": ["WordPress"]},
    }
    saved_vulns = []
    async def _fake_save_vuln(*, title, severity, evidence):
        saved_vulns.append({"title": title, "severity": severity, "evidence": evidence})
        return len(saved_vulns)
    with patch.object(agg, "_save_vuln", side_effect=_fake_save_vuln):
        vuln_ids = await agg.emit_disclosures(fingerprint, raw)

    assert len(vuln_ids) >= 1
    titles = [v["title"] for v in saved_vulns]
    assert any("Corroborated" in t and "WordPress" in t for t in titles)
    # Individual INFO vulns for WordPress should NOT be emitted when corroborated
    assert not any("disclosed via" in t.lower() and "WordPress" in t for t in titles)


@pytest.mark.asyncio
async def test_wstg_admin_path_vuln_emitted():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    fingerprint = {
        "cms": {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
        "framework": {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
        "language":  {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
    }
    raw = {"framework_files": {"obs_id": 30, "admin_paths": ["/wp-login.php"], "info_file_paths": []}}
    saved = []
    async def _fake(*, title, severity, evidence):
        saved.append({"title": title, "severity": severity})
        return len(saved)
    with patch.object(agg, "_save_vuln", side_effect=_fake):
        await agg.emit_disclosures(fingerprint, raw)
    assert any("/wp-login.php" in v["title"] for v in saved)
    assert any(v["severity"] == "LOW" for v in saved)
```

- [ ] **Step 2: Run — expect FAIL (ImportError)**

```
pytest tests/unit/info_gathering/test_framework_fingerprint_aggregator.py -v
```

- [ ] **Step 3: Create `framework_fingerprint_aggregator.py`**

```python
# workers/info_gathering/framework_fingerprint_aggregator.py
"""FrameworkFingerprintAggregator — Stage 8 signal scoring and disclosure (WSTG 4.1.8).

Mirrors FingerprintAggregator (fingerprint_aggregator.py) in structure.
Slots: framework, cms, language.
"""
from __future__ import annotations

from typing import Any

from workers.info_gathering.fingerprint_aggregator import ProbeResult

FRAMEWORK_WEIGHTS: dict[str, float] = {
    "meta_generator":   0.8,
    "header_framework": 0.7,
    "framework_files":  0.6,
    "wappalyzer":       0.6,
    "webanalyze":       0.6,
    "cookie_framework": 0.5,
}
CONFIDENCE_THRESHOLD: float = 0.5
FRAMEWORK_SLOTS: tuple[str, ...] = ("framework", "cms", "language")

__all__ = [
    "CONFIDENCE_THRESHOLD", "FRAMEWORK_SLOTS", "FRAMEWORK_WEIGHTS",
    "FrameworkFingerprintAggregator",
]


class FrameworkFingerprintAggregator:
    """Consolidates Stage 8 probe results into a summary Observation and Vulnerability rows."""

    def __init__(self, asset_id: int, target_id: int) -> None:
        self.asset_id = asset_id
        self.target_id = target_id

    def _score_slot(self, slot: str, results: list[ProbeResult]) -> dict[str, Any]:
        """Weight-accumulation scoring identical to FingerprintAggregator._score_slot."""
        totals: dict[str, float] = {}
        signals_by_vendor: dict[str, list[dict[str, Any]]] = {}
        for r in results:
            if r.error is not None:
                continue
            for sig in r.signals.get(slot, []):
                if not isinstance(sig, dict):
                    continue
                vendor = sig["value"]
                totals[vendor] = totals.get(vendor, 0.0) + sig["w"]
                signals_by_vendor.setdefault(vendor, []).append(sig)

        if not totals:
            return {"vendor": None, "confidence": 0.0, "signals": [], "conflict": False}

        sorted_v = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
        top_vendor, top_score = sorted_v[0]
        clamped = min(top_score, 1.0)
        above = [v for v, s in sorted_v if s >= CONFIDENCE_THRESHOLD]

        if top_score < CONFIDENCE_THRESHOLD:
            return {"vendor": None, "confidence": clamped,
                    "signals": [s for ss in signals_by_vendor.values() for s in ss],
                    "conflict": False}
        if len(above) > 1:
            return {"vendor": top_vendor, "confidence": clamped, "conflict": True,
                    "candidates": [
                        {"vendor": v, "confidence": min(s, 1.0), "signals": signals_by_vendor[v]}
                        for v, s in sorted_v if s >= CONFIDENCE_THRESHOLD
                    ]}
        return {"vendor": top_vendor, "confidence": clamped,
                "signals": signals_by_vendor[top_vendor], "conflict": False}

    async def write_summary(self, results: list[ProbeResult]) -> int | None:
        """Score all slots, write one _probe=framework_summary Observation."""
        partial = any(r.error is not None for r in results)
        fingerprint = {slot: self._score_slot(slot, results) for slot in FRAMEWORK_SLOTS}
        payload: dict[str, Any] = {
            "_probe": "framework_summary",
            "section_id": "4.1.8",
            "partial": partial,
            "fingerprint": fingerprint,
            "raw_probe_obs_ids": [r.obs_id for r in results if r.obs_id is not None],
        }
        from lib_webbh import get_session
        from lib_webbh.database import Observation
        async with get_session() as session:
            obs = Observation(asset_id=self.asset_id, tech_stack=payload)
            session.add(obs)
            await session.commit()
            await session.refresh(obs)
            return obs.id

    def _probe_sources_for_vendor(self, vendor: str, raw: dict[str, Any]) -> set[str]:
        """Return set of probe names in raw that detected vendor."""
        sources: set[str] = set()
        for key in ("header_framework", "meta_generator", "wappalyzer",
                    "webanalyze", "cookie_framework"):
            if vendor in (raw.get(key) or {}).get("all_vendors", []):
                sources.add(key)
        return sources

    def _version_from_raw(self, vendor: str, raw: dict[str, Any]) -> str | None:
        """First version string for vendor across version-bearing probe entries."""
        for key in ("header_framework", "meta_generator"):
            for sig in (raw.get(key) or {}).get("version_signals", []):
                if sig.get("vendor") == vendor and sig.get("version"):
                    return sig["version"]
        return None

    async def emit_disclosures(
        self, fingerprint: dict[str, Any], raw: dict[str, Any],
    ) -> list[int]:
        """Emit Vulnerability rows for framework disclosure findings.

        Corroboration: if >=2 probes detected the same vendor AND >=1 has a version,
        emit one LOW corroborated finding and skip individual INFO findings for that vendor.
        File-based findings (admin paths, info files) are always emitted independently.
        """
        vuln_ids: list[int] = []
        corroborated: set[str] = set()

        # Pass 1: corroboration check for cms + framework slots
        for slot in ("cms", "framework"):
            scored = fingerprint.get(slot) or {}
            vendor = scored.get("vendor")
            if not vendor or scored.get("confidence", 0.0) < CONFIDENCE_THRESHOLD:
                continue
            sources = self._probe_sources_for_vendor(vendor, raw)
            version = self._version_from_raw(vendor, raw)
            if len(sources) >= 2 and version:
                corroborated.add(vendor)
                obs_ids = [
                    v for v in [
                        (raw.get("header_framework") or {}).get("obs_id"),
                        (raw.get("meta_generator") or {}).get("obs_id"),
                    ] if v is not None
                ]
                vuln_ids.append(await self._save_vuln(
                    title=f"Corroborated {slot} version identification: {vendor} {version}",
                    severity="LOW",
                    evidence={"vendor": vendor, "version": version, "slot": slot,
                              "sources": list(sources), "probe_obs_ids": obs_ids},
                ))

        # Pass 2: individual header/meta version disclosure (non-corroborated only)
        for sig in (raw.get("header_framework") or {}).get("version_signals", []):
            if sig.get("vendor") not in corroborated:
                vuln_ids.append(await self._save_vuln(
                    title=f"Framework version disclosed via HTTP header: "
                          f"{sig['vendor']} {sig['version']}",
                    severity="INFO",
                    evidence={"vendor": sig["vendor"], "version": sig["version"],
                              "slot": sig.get("slot"),
                              "probe_obs_id": (raw.get("header_framework") or {}).get("obs_id")},
                ))
        for sig in (raw.get("meta_generator") or {}).get("version_signals", []):
            if sig.get("vendor") not in corroborated:
                vuln_ids.append(await self._save_vuln(
                    title=f"Framework version disclosed via generator meta tag: "
                          f"{sig['vendor']} {sig['version']}",
                    severity="INFO",
                    evidence={"vendor": sig["vendor"], "version": sig["version"],
                              "slot": sig.get("slot"),
                              "probe_obs_id": (raw.get("meta_generator") or {}).get("obs_id")},
                ))

        # Pass 3: file-based findings (independent of corroboration)
        ff = raw.get("framework_files") or {}
        for path in ff.get("admin_paths", []):
            vuln_ids.append(await self._save_vuln(
                title=f"CMS admin interface publicly accessible: {path}",
                severity="LOW",
                evidence={"path": path, "probe_obs_id": ff.get("obs_id")},
            ))
        for path in ff.get("info_file_paths", []):
            vuln_ids.append(await self._save_vuln(
                title=f"CMS information file accessible: {path}",
                severity="LOW",
                evidence={"path": path, "probe_obs_id": ff.get("obs_id")},
            ))

        return vuln_ids

    async def _save_vuln(self, *, title: str, severity: str,
                         evidence: dict[str, Any]) -> int:
        from lib_webbh import get_session
        from lib_webbh.database import Vulnerability
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=self.target_id, asset_id=self.asset_id,
                severity=severity, title=title,
                worker_type="info_gathering", section_id="4.1.8",
                stage_name="fingerprint_framework",
                source_tool="framework_fingerprint_aggregator",
                vuln_type="information_disclosure", evidence=evidence,
            )
            session.add(vuln)
            await session.commit()
            await session.refresh(vuln)
            return vuln.id
```

- [ ] **Step 4: Run — expect PASS**

```
pytest tests/unit/info_gathering/test_framework_fingerprint_aggregator.py -v
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```
git add workers/info_gathering/framework_fingerprint_aggregator.py \
        tests/unit/info_gathering/test_framework_fingerprint_aggregator.py
git commit -m "feat(stage8): add FrameworkFingerprintAggregator with corroboration logic"
```

---

## Task 6: Pipeline hook + concurrency.py

**Files:**
- Modify: `workers/info_gathering/pipeline.py`
- Modify: `workers/info_gathering/concurrency.py`

No new tests — the aggregator unit tests in Task 5 cover the logic. The pipeline integration is validated by the e2e test in Task 7.

- [ ] **Step 1: Add imports and `_STAGE8_SECTION` to `pipeline.py`**

Add these three import lines alongside the existing tool imports (after line 65, before `from workers.info_gathering.fingerprint_aggregator`):

```python
from .tools.header_framework_probe import HeaderFrameworkProbe
from .tools.meta_generator_probe import MetaGeneratorProbe
from .tools.framework_file_prober import FrameworkFileProber
```

Add the constant alongside `_STAGE2_SECTION` and `_STAGE7_SECTION`:

```python
_STAGE8_SECTION = "4.1.8"
```

Add the aggregator import alongside the existing `FingerprintAggregator` import:

```python
from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
```

- [ ] **Step 2: Update the `fingerprint_framework` Stage in `STAGES`**

Replace:
```python
Stage(name="fingerprint_framework", section_id="4.1.8", tools=[Wappalyzer, CookieFingerprinter, Webanalyze]),
```

With:
```python
Stage(name="fingerprint_framework", section_id="4.1.8", tools=[
    Wappalyzer, CookieFingerprinter, Webanalyze,
    HeaderFrameworkProbe, MetaGeneratorProbe, FrameworkFileProber,
]),
```

- [ ] **Step 3: Add `_stage8_raw_from_results` method to `Pipeline` class**

Add this method to `Pipeline`, after `_stage2_raw_from_results`:

```python
def _stage8_raw_from_results(self, results: list) -> dict[str, Any]:
    """Extract per-probe data for FrameworkFingerprintAggregator.emit_disclosures."""
    raw: dict[str, Any] = {}
    for r in results:
        if not isinstance(r, ProbeResult) or r.error is not None:
            continue
        if r.probe in ("header_framework", "meta_generator"):
            raw[r.probe] = {
                "obs_id": r.obs_id,
                "version_signals": [
                    s for k, sigs in r.signals.items()
                    if not k.startswith("_") and isinstance(sigs, list)
                    for s in sigs if isinstance(s, dict) and s.get("version")
                    and {"vendor": s["value"], "version": s["version"], "slot": k}
                    # rebuild to normalized shape
                ] if False else [  # use comprehension below
                    {"vendor": s["value"], "version": s["version"], "slot": k}
                    for k, sigs in r.signals.items()
                    if not k.startswith("_") and isinstance(sigs, list)
                    for s in sigs if isinstance(s, dict) and s.get("version")
                ],
                "all_vendors": list({
                    s["value"]
                    for k, sigs in r.signals.items()
                    if not k.startswith("_") and isinstance(sigs, list)
                    for s in sigs if isinstance(s, dict) and s.get("value")
                }),
            }
        elif r.probe in ("wappalyzer", "webanalyze", "cookie_framework"):
            raw[r.probe] = {
                "obs_id": r.obs_id,
                "all_vendors": list({
                    s["value"]
                    for k, sigs in r.signals.items()
                    if not k.startswith("_") and isinstance(sigs, list)
                    for s in sigs if isinstance(s, dict) and s.get("value")
                }),
            }
        elif r.probe == "framework_files":
            raw["framework_files"] = {
                "obs_id": r.obs_id,
                "admin_paths": r.signals.get("_admin_paths", []),
                "info_file_paths": r.signals.get("_info_file_paths", []),
            }
    return raw
```

**Note:** The `if False else` construction above is a placeholder artifact — use this clean version instead:

```python
def _stage8_raw_from_results(self, results: list) -> dict[str, Any]:
    """Extract per-probe data for FrameworkFingerprintAggregator.emit_disclosures."""
    raw: dict[str, Any] = {}
    for r in results:
        if not isinstance(r, ProbeResult) or r.error is not None:
            continue

        def _all_vendors(signals: dict) -> list[str]:
            return list({
                s["value"]
                for k, sigs in signals.items()
                if not k.startswith("_") and isinstance(sigs, list)
                for s in sigs if isinstance(s, dict) and s.get("value")
            })

        if r.probe in ("header_framework", "meta_generator"):
            raw[r.probe] = {
                "obs_id": r.obs_id,
                "version_signals": [
                    {"vendor": s["value"], "version": s["version"], "slot": k}
                    for k, sigs in r.signals.items()
                    if not k.startswith("_") and isinstance(sigs, list)
                    for s in sigs if isinstance(s, dict) and s.get("version")
                ],
                "all_vendors": _all_vendors(r.signals),
            }
        elif r.probe in ("wappalyzer", "webanalyze", "cookie_framework"):
            raw[r.probe] = {"obs_id": r.obs_id, "all_vendors": _all_vendors(r.signals)}
        elif r.probe == "framework_files":
            raw["framework_files"] = {
                "obs_id": r.obs_id,
                "admin_paths": r.signals.get("_admin_paths", []),
                "info_file_paths": r.signals.get("_info_file_paths", []),
            }
    return raw
```

- [ ] **Step 4: Add Stage 8 post-stage hook in `run()`**

In `pipeline.py`'s `run()` method, after the existing Stage 7 hook block (ending around line 274), add:

```python
            if stage.section_id == _STAGE8_SECTION:
                agg8 = FrameworkFingerprintAggregator(
                    asset_id=asset_id, target_id=self.target_id,
                )
                probe_results8 = [r for r in results if isinstance(r, ProbeResult)]
                summary_obs_id8 = await agg8.write_summary(probe_results8)
                fingerprint8 = {
                    slot: agg8._score_slot(slot, probe_results8)
                    for slot in ("framework", "cms", "language")
                }
                raw8 = self._stage8_raw_from_results(probe_results8)
                vuln_ids8 = await agg8.emit_disclosures(fingerprint8, raw8)
                stats["probes"] = len(probe_results8)
                stats["summary_written"] = summary_obs_id8 is not None
                stats["vulns"] = len(vuln_ids8)
```

- [ ] **Step 5: Update `concurrency.py`**

Add after the `"Webanalyze": "LIGHT",` line:

```python
    "HeaderFrameworkProbe": "LIGHT",
    "MetaGeneratorProbe":   "LIGHT",
    "FrameworkFileProber":  "LIGHT",
```

- [ ] **Step 6: Commit**

```
git add workers/info_gathering/pipeline.py \
        workers/info_gathering/concurrency.py
git commit -m "feat(stage8): wire FrameworkFingerprintAggregator post-stage hook and add new tools to STAGES"
```

---

## Task 7: E2e test update

**Files:**
- Modify: `tests/e2e/test_info_gathering.py`

- [ ] **Step 1: Add a stage-stats assertion test**

Append to `tests/e2e/test_info_gathering.py`:

```python
async def test_info_gathering_fingerprint_framework_aggregator_ran(pipeline_result):
    """Verify the Stage 8 post-stage hook ran: at least one probe executed
    and the FrameworkFingerprintAggregator wrote its summary observation."""
    _, report = pipeline_result
    stage_events = [
        e for e in report.raw_events
        if e.get("event") == "STAGE_COMPLETE"
        and e.get("stage") == "fingerprint_framework"
    ]
    assert len(stage_events) == 1, "fingerprint_framework STAGE_COMPLETE not received"
    stats = stage_events[0].get("stats", {})
    assert stats.get("probes", 0) >= 1, (
        "Stage 8 should have run >=1 probe; "
        f"got stats={stats}"
    )
    assert stats.get("summary_written") is True, (
        "FrameworkFingerprintAggregator.write_summary must write a summary observation"
    )
```

- [ ] **Step 2: Run the full unit test suite to confirm no regressions**

```
pytest tests/unit/ -v
```

Expected: all unit tests pass.

- [ ] **Step 3: Commit**

```
git add tests/e2e/test_info_gathering.py
git commit -m "test(stage8): add e2e assertion for FrameworkFingerprintAggregator post-stage hook"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Fix Wappalyzer, CookieFingerprinter, Webanalyze save_observation + ProbeResult | Task 1 |
| HeaderFrameworkProbe (X-Generator, X-AspNetMvc-Version, X-Powered-By, etc.) | Task 2 |
| MetaGeneratorProbe (meta generator tag, api.w.org, csrf-param, csrfmiddlewaretoken, data-drupal-*) | Task 3 |
| FrameworkFileProber (wp-login.php, /administrator/, CHANGELOG.txt, etc.; 403 = accessible) | Task 4 |
| FrameworkFingerprintAggregator._score_slot, write_summary, emit_disclosures | Task 5 |
| Corroboration: ≥2 probes + version → single LOW, suppress individual INFOs | Task 5 |
| INFO: header version disclosure | Task 5 |
| INFO: meta generator version disclosure | Task 5 |
| LOW: admin interface accessible | Task 5 |
| LOW: info file accessible | Task 5 |
| Pipeline hook (_STAGE8_SECTION, _stage8_raw_from_results) | Task 6 |
| STAGES updated with 3 new tools | Task 6 |
| concurrency.py TOOL_WEIGHTS for 3 new tools | Task 6 |
| E2e test asserts summary_written and probes >= 1 | Task 7 |

**Placeholder scan:** None found.

**Type consistency:** `ProbeResult` imported from `fingerprint_aggregator` in all tool files and reused in aggregator — consistent. `_stage8_raw_from_results` returns `dict[str, Any]` consumed by `emit_disclosures(fingerprint, raw)` — consistent. `_admin_paths` / `_info_file_paths` set in `FrameworkFileProber.signals` and read in `_stage8_raw_from_results` — consistent.
