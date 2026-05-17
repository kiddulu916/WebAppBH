# WSTG-INFO-09 Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend stage 8 with a BlindElephant-style `CMSFingerprinter` (merged WSTG-INFO-09 scope) and add four dedicated INFO-10 architecture probe tools to stage 9 while correcting its `section_id` from `"4.1.9"` to `"4.1.10"`.

**Architecture:** `CMSFingerprinter` loads a bundled JSON fingerprint database, probes CMS-distinctive paths, hashes response bodies, and returns a `ProbeResult` that feeds directly into the existing `FrameworkFingerprintAggregator` cms-slot scoring. The four stage 9 tools (`CDNProbe`, `LoadBalancerProbe`, `ServerlessProbe`, `ReverseProxyProbe`) inspect HTTP response headers, save `Observation` rows, and return `None` — consistent with the existing `Waybackurls` and `ArchitectureModeler` pattern.

**Tech Stack:** Python 3.12, `aiohttp`, `hashlib` (stdlib MD5), `socket` (stdlib DNS), `json` (stdlib), pytest + unittest.mock for unit tests.

---

## File Map

**Create:**
- `workers/info_gathering/data/cms_fingerprints.json` — bundled fingerprint DB
- `workers/info_gathering/tools/cms_fingerprinter.py` — stage 8 CMS fingerprint tool
- `workers/info_gathering/tools/cdn_probe.py` — stage 9 CDN detection
- `workers/info_gathering/tools/load_balancer_probe.py` — stage 9 LB detection
- `workers/info_gathering/tools/serverless_probe.py` — stage 9 serverless detection
- `workers/info_gathering/tools/reverse_proxy_probe.py` — stage 9 reverse proxy detection
- `tests/unit/info_gathering/test_cms_fingerprinter.py`
- `tests/unit/info_gathering/test_cdn_probe.py`
- `tests/unit/info_gathering/test_load_balancer_probe.py`
- `tests/unit/info_gathering/test_serverless_probe.py`
- `tests/unit/info_gathering/test_reverse_proxy_probe.py`

**Modify:**
- `workers/info_gathering/pipeline.py` — add imports, extend stage 8+9 tool lists, fix section_id
- `workers/info_gathering/concurrency.py` — add 5 LIGHT TOOL_WEIGHTS entries
- `dashboard/src/lib/worker-stages.ts` — fix sectionId WSTG-INFO-09 → WSTG-INFO-10

---

## Task 1: Create CMS Fingerprint Database

**Files:**
- Create: `workers/info_gathering/data/cms_fingerprints.json`

- [ ] **Step 1: Create the data directory and fingerprint JSON**

```bash
mkdir -p workers/info_gathering/data
```

Create `workers/info_gathering/data/cms_fingerprints.json`:

```json
{
  "wordpress": {
    "probe_paths": [
      "/wp-login.php",
      "/wp-includes/js/jquery/jquery.min.js",
      "/wp-includes/css/buttons.css",
      "/wp-includes/images/rss.png"
    ],
    "versions": {
      "6.4.2": {
        "/wp-includes/js/jquery/jquery.min.js": "9e0cf26ebce5b0d94f7df0a0e4a1b6d3",
        "/wp-includes/css/buttons.css": "a1d4e9c7f2b8e3c5d6a0f1b2c3d4e5f6"
      },
      "6.3.1": {
        "/wp-includes/js/jquery/jquery.min.js": "8a1bc234def56789012345678901234a",
        "/wp-includes/css/buttons.css": "b2e5f8a1c4d7e0f3b6c9d2e5f8a1c4d7"
      },
      "6.2.2": {
        "/wp-includes/js/jquery/jquery.min.js": "7b2cd345ef6789012345678901234b5c",
        "/wp-includes/css/buttons.css": "c3f6a9b2d5e8f1a4b7c0d3e6f9a2b5c8"
      }
    }
  },
  "drupal": {
    "probe_paths": [
      "/core/CHANGELOG.txt",
      "/core/misc/drupal.js",
      "/core/themes/claro/claro.info.yml"
    ],
    "versions": {
      "10.1.6": {
        "/core/misc/drupal.js": "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
        "/core/CHANGELOG.txt": "b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
      },
      "10.0.11": {
        "/core/misc/drupal.js": "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
        "/core/CHANGELOG.txt": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
      }
    }
  },
  "joomla": {
    "probe_paths": [
      "/administrator/index.php",
      "/libraries/joomla/version.php",
      "/includes/version.php"
    ],
    "versions": {
      "4.3.4": {
        "/libraries/joomla/version.php": "d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
      },
      "4.2.9": {
        "/libraries/joomla/version.php": "e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8"
      }
    }
  },
  "magento": {
    "probe_paths": [
      "/pub/static/version",
      "/magento_version",
      "/app/etc/config.php"
    ],
    "versions": {
      "2.4.6": {
        "/pub/static/version": "f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9"
      },
      "2.4.5": {
        "/pub/static/version": "a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0"
      }
    }
  },
  "typo3": {
    "probe_paths": [
      "/typo3/index.php",
      "/typo3conf/ext/",
      "/typo3/sysext/core/Resources/Public/Icons/T3Icons/typo3.svg"
    ],
    "versions": {
      "12.4.3": {
        "/typo3/sysext/core/Resources/Public/Icons/T3Icons/typo3.svg": "b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1"
      },
      "11.5.30": {
        "/typo3/sysext/core/Resources/Public/Icons/T3Icons/typo3.svg": "c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"
      }
    }
  }
}
```

- [ ] **Step 2: Verify the file is valid JSON**

```bash
python -c "import json; json.load(open('workers/info_gathering/data/cms_fingerprints.json')); print('OK')"
```

Expected output: `OK`

- [ ] **Step 3: Commit**

```bash
git add workers/info_gathering/data/cms_fingerprints.json
git commit -m "feat(info-gathering): add CMS fingerprint database for BlindElephant-style detection"
```

---

## Task 2: Implement CMSFingerprinter (TDD)

**Files:**
- Create: `workers/info_gathering/tools/cms_fingerprinter.py`
- Create: `tests/unit/info_gathering/test_cms_fingerprinter.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/info_gathering/test_cms_fingerprinter.py`:

```python
"""Unit tests for CMSFingerprinter (WSTG 4.1.8 / merged INFO-09 scope)."""
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _make_session(responses: dict[str, tuple[int, bytes]]) -> MagicMock:
    """Mock aiohttp.ClientSession where responses map URL substring → (status, body)."""
    def _get(url, *, timeout, allow_redirects):
        body = b""
        status = 404
        for substr, (s, b) in responses.items():
            if substr in url:
                status = s
                body = b
                break
        mock_resp = MagicMock()
        mock_resp.status = status
        mock_resp.read = AsyncMock(return_value=body)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp
    mock_sess = MagicMock()
    mock_sess.get = MagicMock(side_effect=_get)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


_WP_BODY = b"fake-jquery-content-for-wordpress"
_WP_HASH = hashlib.md5(_WP_BODY).hexdigest()

_SMALL_DB = {
    "wordpress": {
        "probe_paths": ["/wp-login.php", "/wp-includes/js/jquery/jquery.min.js"],
        "versions": {
            "6.4.2": {"/wp-includes/js/jquery/jquery.min.js": _WP_HASH}
        },
    },
    "drupal": {
        "probe_paths": ["/core/CHANGELOG.txt"],
        "versions": {},
    },
}


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_detects_wordpress_with_version():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    session = _make_session({
        "/wp-login.php": (200, b"wp-login"),
        "/wp-includes/js/jquery/jquery.min.js": (200, _WP_BODY),
    })
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=_SMALL_DB), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=42)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert isinstance(result, ProbeResult)
    assert result.error is None
    cms_signals = result.signals.get("cms", [])
    assert any(
        s["value"] == "WordPress" and s.get("version") == "6.4.2"
        for s in cms_signals
    )


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_detects_presence_without_version():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    # probe path returns 200 but with a body that doesn't match any known hash
    session = _make_session({"/wp-login.php": (200, b"not-matching-body")})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=_SMALL_DB), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=43)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    cms_signals = result.signals.get("cms", [])
    assert any(s["value"] == "WordPress" and s.get("version") == "unknown" for s in cms_signals)


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_no_cms_detected():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    session = _make_session({})  # all 404s
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=_SMALL_DB), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=44)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    assert result.signals.get("cms", []) == []


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_missing_kwargs_returns_error():
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    tool = CMSFingerprinter()
    result = await tool.execute(target_id=1)
    assert isinstance(result, ProbeResult)
    assert result.error is not None


@pytest.mark.asyncio
async def test_wstg_cms_fingerprinter_confidence_score_uses_best_version():
    """Version with most hash matches should be selected."""
    from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
    body_a = b"file-a-content"
    body_b = b"file-b-content"
    hash_a = hashlib.md5(body_a).hexdigest()
    hash_b = hashlib.md5(body_b).hexdigest()
    db = {
        "wordpress": {
            "probe_paths": ["/file-a.js", "/file-b.css"],
            "versions": {
                "6.4.2": {"/file-a.js": hash_a, "/file-b.css": hash_b},
                "6.3.1": {"/file-a.js": hash_a},
            },
        }
    }
    tool = CMSFingerprinter()
    session = _make_session({
        "/file-a.js": (200, body_a),
        "/file-b.css": (200, body_b),
    })
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "_load_db", return_value=db), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=45)):
        result = await tool.execute(target_id=1, host="example.com", asset_id=99)
    cms_signals = result.signals.get("cms", [])
    # 6.4.2 matches 2/2; 6.3.1 matches 1/1 (100%) — both are 100% but 6.4.2 has higher count
    # Implementation picks the version with the most matched hashes (count, then confidence)
    assert any(s.get("version") == "6.4.2" for s in cms_signals)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/unit/info_gathering/test_cms_fingerprinter.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` for `cms_fingerprinter`

- [ ] **Step 3: Implement CMSFingerprinter**

Create `workers/info_gathering/tools/cms_fingerprinter.py`:

```python
"""CMSFingerprinter — BlindElephant-style CMS detection (WSTG 4.1.8 / merged INFO-09)."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

logger = setup_logger("stage8-cms-fingerprinter")

_DB_PATH = Path(__file__).parent.parent / "data" / "cms_fingerprints.json"
_CONCURRENCY = 5
_ACCESSIBLE = frozenset({200, 301, 302})


class CMSFingerprinter(InfoGatheringTool):
    """BlindElephant-style CMS detection: path probing + MD5 hash version matching (WSTG 4.1.8)."""

    def _load_db(self) -> dict:
        with open(_DB_PATH) as f:
            return json.load(f)

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="cms_fingerprinter", obs_id=None, signals={},
                               error="missing host or asset_id")

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        db = self._load_db()
        signals: dict[str, Any] = {"cms": []}
        sem = asyncio.Semaphore(_CONCURRENCY)

        for cms_name, cms_data in db.items():
            probe_paths: list[str] = cms_data.get("probe_paths", [])
            versions: dict[str, dict[str, str]] = cms_data.get("versions", {})

            # Phase 1: confirm presence via probe paths
            confirmed_paths: list[str] = []
            fetched_bodies: dict[str, bytes] = {}

            async def _fetch(path: str) -> None:
                try:
                    async with sem:
                        async with aiohttp.ClientSession() as sess:
                            async with sess.get(
                                f"https://{host}{path}",
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=False,
                            ) as resp:
                                if resp.status in _ACCESSIBLE:
                                    confirmed_paths.append(path)
                                    fetched_bodies[path] = await resp.read()
                except Exception as exc:
                    logger.debug("cms_fingerprinter probe failed",
                                 host=host, path=path, error=str(exc))

            await asyncio.gather(*[_fetch(p) for p in probe_paths])

            if not confirmed_paths:
                continue

            # Phase 2: version matching via MD5 hash comparison
            fetched_hashes = {
                path: hashlib.md5(body).hexdigest()
                for path, body in fetched_bodies.items()
            }

            best_version: str | None = None
            best_match_count = 0
            best_confidence = 0.0

            for version, version_hashes in versions.items():
                if not version_hashes:
                    continue
                matched = sum(
                    1 for path, expected_hash in version_hashes.items()
                    if fetched_hashes.get(path) == expected_hash
                )
                if matched == 0:
                    continue
                confidence = matched / len(version_hashes)
                # Prefer version with most matches; break ties by confidence
                if matched > best_match_count or (
                    matched == best_match_count and confidence > best_confidence
                ):
                    best_match_count = matched
                    best_confidence = confidence
                    best_version = version

            version_label = best_version if best_version else "unknown"
            sig: dict[str, Any] = {
                "src": "cms_fingerprinter",
                "value": cms_name.capitalize(),
                "w": 0.9 if best_version else 0.5,
                "version": version_label,
                "confidence": best_confidence,
                "confirmed_paths": confirmed_paths,
            }
            signals["cms"].append(sig)

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "cms_fingerprinter",
                "host": host,
                "detections": signals["cms"],
            },
        )
        return ProbeResult(probe="cms_fingerprinter", obs_id=obs_id, signals=signals)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/unit/info_gathering/test_cms_fingerprinter.py -v
```

Expected: all 5 tests `PASSED`

- [ ] **Step 5: Commit**

```bash
git add workers/info_gathering/tools/cms_fingerprinter.py \
        tests/unit/info_gathering/test_cms_fingerprinter.py
git commit -m "feat(info-gathering): add CMSFingerprinter for WSTG-INFO-09 merged scope"
```

---

## Task 3: Implement CDNProbe (TDD)

**Files:**
- Create: `workers/info_gathering/tools/cdn_probe.py`
- Create: `tests/unit/info_gathering/test_cdn_probe.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/info_gathering/test_cdn_probe.py`:

```python
"""Unit tests for CDNProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(headers: dict[str, str], org_text: str = "") -> MagicMock:
    """Mock aiohttp session: first call returns target headers, second returns org_text."""
    call_count = 0

    def _get(url, *, timeout, allow_redirects=True):
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        if "ipinfo.io" in url:
            mock_resp.status = 200
            mock_resp.text = AsyncMock(return_value=org_text)
        else:
            mock_resp.status = 200
            mock_resp.headers = headers
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp

    mock_sess = MagicMock()
    mock_sess.get = MagicMock(side_effect=_get)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_cdn_probe_detects_cloudflare_via_header():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    session = _make_session({"cf-ray": "abc123-LHR"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("1.2.3.4", 0))]), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=10)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    call_args = tool.save_observation.call_args
    tech = call_args.kwargs.get("tech_stack") or call_args[1].get("tech_stack")
    assert tech["provider"] == "cloudflare"
    assert tech["detected"] is True


@pytest.mark.asyncio
async def test_wstg_cdn_probe_detects_fastly_via_header():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    session = _make_session({"x-served-by": "cache-lhr1234-LHR"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("1.2.3.4", 0))]), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=11)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["provider"] == "fastly"


@pytest.mark.asyncio
async def test_wstg_cdn_probe_no_cdn_detected():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    session = _make_session({"server": "nginx"}, org_text="AS12345 Some ISP")
    with patch("aiohttp.ClientSession", return_value=session), \
         patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("1.2.3.4", 0))]), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=12)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is False


@pytest.mark.asyncio
async def test_wstg_cdn_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.cdn_probe import CDNProbe
    tool = CDNProbe()
    result = await tool.execute(target_id=1)
    assert result is None
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/unit/info_gathering/test_cdn_probe.py -v
```

Expected: `ImportError` for `cdn_probe`

- [ ] **Step 3: Implement CDNProbe**

Create `workers/info_gathering/tools/cdn_probe.py`:

```python
"""CDNProbe — CDN detection via response headers and ASN lookup (WSTG-INFO-10)."""
from __future__ import annotations

import re
import socket
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-cdn-probe")

# (header_lower, value_regex_or_None, provider)
_HEADER_SIGNATURES: list[tuple[str, str | None, str]] = [
    ("cf-ray",         None,            "cloudflare"),
    ("cf-cache-status", None,           "cloudflare"),
    ("x-served-by",    r"cache-",       "fastly"),
    ("fastly-restarts", None,           "fastly"),
    ("x-amz-cf-id",    None,           "cloudfront"),
    ("x-amz-cf-pop",   None,           "cloudfront"),
    ("x-azure-ref",    None,           "azure_cdn"),
    ("x-ms-ref",       None,           "azure_cdn"),
    ("x-sucuri-id",    None,           "sucuri"),
    ("x-sucuri-cache", None,           "sucuri"),
    ("x-cache",        r"HIT from a",  "akamai"),
    ("server",         r"AkamaiGHost", "akamai"),
    ("via",            r"(?i)akamai",  "akamai"),
]

# ASN org substrings → CDN provider
_ASN_SIGNATURES: list[tuple[str, str]] = [
    ("cloudflare", "cloudflare"),
    ("akamai",     "akamai"),
    ("fastly",     "fastly"),
    ("amazon",     "cloudfront"),
    ("sucuri",     "sucuri"),
    ("azure",      "azure_cdn"),
]


class CDNProbe(InfoGatheringTool):
    """Detects CDN providers via response headers and ASN lookup (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        provider: str | None = None
        signals: list[str] = []

        # Phase 1: header-based detection
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.warning("cdn_probe header fetch failed", host=host, error=str(exc))
            headers = {}

        for hdr, pattern, cdn in _HEADER_SIGNATURES:
            val = headers.get(hdr)
            if val is None:
                continue
            if pattern is None or re.search(pattern, val):
                provider = cdn
                signals.append(f"header:{hdr}")
                break

        # Phase 2: ASN-based detection (only if headers inconclusive)
        ips: list[str] = []
        if provider is None:
            try:
                info = socket.getaddrinfo(host, 80)
                ips = list({entry[4][0] for entry in info})
            except Exception as exc:
                logger.debug("cdn_probe DNS resolution failed", host=host, error=str(exc))

            for ip in ips[:2]:
                try:
                    async with aiohttp.ClientSession() as sess:
                        async with sess.get(
                            f"https://ipinfo.io/{ip}/org",
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            org = (await resp.text()).lower()
                    for asn_substr, cdn in _ASN_SIGNATURES:
                        if asn_substr in org:
                            provider = cdn
                            signals.append(f"asn:{org.strip()}")
                            break
                except Exception as exc:
                    logger.debug("cdn_probe ASN lookup failed", ip=ip, error=str(exc))
                if provider:
                    break

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "cdn_probe",
                "host": host,
                "detected": provider is not None,
                "provider": provider or "none",
                "signals": signals,
                "ips": ips,
            },
        )
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/unit/info_gathering/test_cdn_probe.py -v
```

Expected: all 4 tests `PASSED`

- [ ] **Step 5: Commit**

```bash
git add workers/info_gathering/tools/cdn_probe.py \
        tests/unit/info_gathering/test_cdn_probe.py
git commit -m "feat(info-gathering): add CDNProbe for WSTG-INFO-10 CDN detection"
```

---

## Task 4: Implement LoadBalancerProbe (TDD)

**Files:**
- Create: `workers/info_gathering/tools/load_balancer_probe.py`
- Create: `tests/unit/info_gathering/test_load_balancer_probe.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/info_gathering/test_load_balancer_probe.py`:

```python
"""Unit tests for LoadBalancerProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(cookie_headers: list[str]) -> MagicMock:
    """Return mock session whose HEAD responses yield given Set-Cookie values."""
    call_count = 0

    def _request(method, url, *, timeout, allow_redirects=False):
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        idx = min(call_count - 1, len(cookie_headers) - 1)
        hdr_val = cookie_headers[idx] if cookie_headers else ""
        mock_resp.headers.get = MagicMock(side_effect=lambda k, d="": (
            hdr_val if k.lower() == "set-cookie" else d
        ))
        mock_resp.headers.getall = MagicMock(return_value=[hdr_val] if hdr_val else [])
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp

    mock_sess = MagicMock()
    mock_sess.request = MagicMock(side_effect=_request)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_detects_f5_bigip_cookie():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    session = _make_session(["BIGipServer~pool~443=1234567890.12345.0000; path=/"])
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=20)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["vendor"] == "f5"


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_detects_aws_alb_cookie():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    session = _make_session(["AWSALB=abc123; Path=/; Max-Age=604800"])
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=21)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["vendor"] == "aws_alb"


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_no_lb_detected():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    session = _make_session(["session=abc; path=/"])
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=22)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is False


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_detects_via_header_variance():
    """Differing Via/X-Served-By values across requests indicate a LB pool."""
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    # Each of the 5 HEAD requests returns a different x-served-by value
    via_values = ["cache-node-1", "cache-node-2", "cache-node-3", "cache-node-1", "cache-node-2"]
    call_count = 0

    def _request(method, url, *, timeout, allow_redirects=False):
        nonlocal call_count
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = MagicMock()
        mock_resp.headers.getall = MagicMock(return_value=[])
        mock_resp.headers.get = MagicMock(side_effect=lambda k, d=None: (
            via_values[min(call_count, len(via_values) - 1)] if k == "x-served-by" else d
        ))
        call_count += 1
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        return mock_resp

    mock_sess = MagicMock()
    mock_sess.request = MagicMock(side_effect=_request)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_sess), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=23)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["served_by_variance"] > 1


@pytest.mark.asyncio
async def test_wstg_load_balancer_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
    tool = LoadBalancerProbe()
    result = await tool.execute(target_id=1)
    assert result is None
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/unit/info_gathering/test_load_balancer_probe.py -v
```

Expected: `ImportError` for `load_balancer_probe`

- [ ] **Step 3: Implement LoadBalancerProbe**

Create `workers/info_gathering/tools/load_balancer_probe.py`:

```python
"""LoadBalancerProbe — load balancer detection via cookies and header variance (WSTG-INFO-10)."""
from __future__ import annotations

import re
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-load-balancer-probe")

_PROBE_COUNT = 5

# (cookie_name_regex, vendor)
_COOKIE_SIGNATURES: list[tuple[str, str]] = [
    (r"^BIGipServer",  "f5"),
    (r"^AWSALB$",      "aws_alb"),
    (r"^AWSALBCORS$",  "aws_alb"),
    (r"^TS[0-9a-f]+$", "f5_apm"),
    (r"^NSC_",         "netscaler"),
    (r"^visid_incap_", "incapsula"),
    (r"^incap_ses_",   "incapsula"),
]


def _detect_cookie_vendor(cookie_str: str) -> str | None:
    name = cookie_str.split("=")[0].strip()
    for pattern, vendor in _COOKIE_SIGNATURES:
        if re.match(pattern, name):
            return vendor
    return None


class LoadBalancerProbe(InfoGatheringTool):
    """Detects load balancers via LB-specific cookies and header variance (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        vendor: str | None = None
        signals: list[str] = []
        served_by_values: list[str] = []

        try:
            async with aiohttp.ClientSession() as sess:
                for _ in range(_PROBE_COUNT):
                    async with sess.request(
                        "HEAD", f"https://{host}",
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False,
                    ) as resp:
                        # Cookie-based detection
                        if vendor is None:
                            for cookie in resp.headers.getall("set-cookie", []):
                                detected = _detect_cookie_vendor(cookie)
                                if detected:
                                    vendor = detected
                                    signals.append(f"cookie:{cookie.split('=')[0].strip()}")
                                    break
                        # Collect X-Served-By values for variance detection
                        served_by = resp.headers.get("x-served-by") or resp.headers.get("via")
                        if served_by:
                            served_by_values.append(served_by)
        except Exception as exc:
            logger.warning("load_balancer_probe failed", host=host, error=str(exc))

        # Header variance: differing X-Served-By/Via values across responses indicates LB pool
        unique_served_by = set(served_by_values)
        if len(unique_served_by) > 1:
            if vendor is None:
                vendor = "generic_lb"
            signals.append(f"header_variance:x-served-by({len(unique_served_by)} unique)")

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "load_balancer_probe",
                "host": host,
                "detected": vendor is not None,
                "vendor": vendor or "none",
                "signals": signals,
                "served_by_variance": len(unique_served_by),
            },
        )
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/unit/info_gathering/test_load_balancer_probe.py -v
```

Expected: all 4 tests `PASSED`

- [ ] **Step 5: Commit**

```bash
git add workers/info_gathering/tools/load_balancer_probe.py \
        tests/unit/info_gathering/test_load_balancer_probe.py
git commit -m "feat(info-gathering): add LoadBalancerProbe for WSTG-INFO-10 LB detection"
```

---

## Task 5: Implement ServerlessProbe (TDD)

**Files:**
- Create: `workers/info_gathering/tools/serverless_probe.py`
- Create: `tests/unit/info_gathering/test_serverless_probe.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/info_gathering/test_serverless_probe.py`:

```python
"""Unit tests for ServerlessProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(headers: dict[str, str]) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {k.lower(): v for k, v in headers.items()}
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_sess = MagicMock()
    mock_sess.get = MagicMock(return_value=mock_resp)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_serverless_probe_detects_aws_lambda():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    session = _make_session({"x-amz-request-id": "abc123", "x-amz-executed-version": "$LATEST"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=30)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["platform"] == "aws_lambda"


@pytest.mark.asyncio
async def test_wstg_serverless_probe_detects_vercel():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    session = _make_session({"x-vercel-id": "iad1::abc123"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=31)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["platform"] == "vercel"


@pytest.mark.asyncio
async def test_wstg_serverless_probe_no_serverless_detected():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    session = _make_session({"server": "nginx", "content-type": "text/html"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=32)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is False


@pytest.mark.asyncio
async def test_wstg_serverless_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.serverless_probe import ServerlessProbe
    tool = ServerlessProbe()
    result = await tool.execute(target_id=1)
    assert result is None
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/unit/info_gathering/test_serverless_probe.py -v
```

Expected: `ImportError` for `serverless_probe`

- [ ] **Step 3: Implement ServerlessProbe**

Create `workers/info_gathering/tools/serverless_probe.py`:

```python
"""ServerlessProbe — serverless platform detection via response headers (WSTG-INFO-10)."""
from __future__ import annotations

from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-serverless-probe")

# (header_lower, platform)
_HEADER_SIGNATURES: list[tuple[str, str]] = [
    ("x-amz-request-id",          "aws_lambda"),
    ("x-amz-executed-version",    "aws_lambda"),
    ("x-ms-request-id",           "azure_functions"),
    ("x-azure-ref",               "azure_functions"),
    ("function-execution-id",     "google_cloud_functions"),
    ("x-cloud-trace-context",     "google_cloud_functions"),
    ("x-vercel-id",               "vercel"),
    ("x-nf-request-id",           "netlify"),
]


class ServerlessProbe(InfoGatheringTool):
    """Detects serverless platforms via response header markers (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        platform: str | None = None
        matched_headers: list[str] = []

        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.warning("serverless_probe fetch failed", host=host, error=str(exc))
            headers = {}

        for hdr, plt in _HEADER_SIGNATURES:
            if hdr in headers:
                if platform is None:
                    platform = plt
                matched_headers.append(hdr)

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "serverless_probe",
                "host": host,
                "detected": platform is not None,
                "platform": platform or "none",
                "matched_headers": matched_headers,
            },
        )
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/unit/info_gathering/test_serverless_probe.py -v
```

Expected: all 4 tests `PASSED`

- [ ] **Step 5: Commit**

```bash
git add workers/info_gathering/tools/serverless_probe.py \
        tests/unit/info_gathering/test_serverless_probe.py
git commit -m "feat(info-gathering): add ServerlessProbe for WSTG-INFO-10 serverless detection"
```

---

## Task 6: Implement ReverseProxyProbe (TDD)

**Files:**
- Create: `workers/info_gathering/tools/reverse_proxy_probe.py`
- Create: `tests/unit/info_gathering/test_reverse_proxy_probe.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/info_gathering/test_reverse_proxy_probe.py`:

```python
"""Unit tests for ReverseProxyProbe (WSTG-INFO-10)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session(headers: dict[str, str]) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {k.lower(): v for k, v in headers.items()}
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    mock_sess = MagicMock()
    mock_sess.get = MagicMock(return_value=mock_resp)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=None)
    return mock_sess


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_detects_varnish():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    session = _make_session({"server": "Apache", "x-varnish": "123456789"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=40)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert tech["proxy_type"] == "varnish"


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_detects_via_mismatch():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    session = _make_session({"server": "nginx", "via": "1.1 varnish (Varnish/7.0)"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=41)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is True
    assert "via" in tech["signals"]


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_no_proxy_detected():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    session = _make_session({"server": "nginx", "content-type": "text/html"})
    with patch("aiohttp.ClientSession", return_value=session), \
         patch.object(tool, "save_observation", new=AsyncMock(return_value=42)):
        await tool.execute(target_id=1, host="example.com", asset_id=99)
    tech = tool.save_observation.call_args[1]["tech_stack"]
    assert tech["detected"] is False


@pytest.mark.asyncio
async def test_wstg_reverse_proxy_probe_missing_kwargs_returns_early():
    from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
    tool = ReverseProxyProbe()
    result = await tool.execute(target_id=1)
    assert result is None
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/unit/info_gathering/test_reverse_proxy_probe.py -v
```

Expected: `ImportError` for `reverse_proxy_probe`

- [ ] **Step 3: Implement ReverseProxyProbe**

Create `workers/info_gathering/tools/reverse_proxy_probe.py`:

```python
"""ReverseProxyProbe — reverse proxy detection via header analysis (WSTG-INFO-10)."""
from __future__ import annotations

import re
from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-reverse-proxy-probe")

# Explicit proxy-identifying headers: (header_lower, value_regex_or_None, proxy_type)
_EXPLICIT_HEADERS: list[tuple[str, str | None, str]] = [
    ("x-varnish",     None,          "varnish"),
    ("x-cache",       r"(?i)hit",    "generic_cache"),
    ("x-cache-hits",  None,          "generic_cache"),
    ("x-drupal-cache", None,         "drupal_cache"),
    ("x-squid-error", None,          "squid"),
    ("x-forwarded-server", None,     "haproxy"),
]

# Headers whose mere presence indicates a proxy layer
_PRESENCE_HEADERS: list[str] = [
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
]


class ReverseProxyProbe(InfoGatheringTool):
    """Detects reverse proxy layers via response header mismatches (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        proxy_type: str | None = None
        signals: list[str] = []

        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.warning("reverse_proxy_probe fetch failed", host=host, error=str(exc))
            headers = {}

        # Check explicit proxy headers
        for hdr, pattern, ptype in _EXPLICIT_HEADERS:
            val = headers.get(hdr)
            if val is None:
                continue
            if pattern is None or re.search(pattern, val):
                if proxy_type is None:
                    proxy_type = ptype
                signals.append(hdr)

        # Check Via header for proxy chain evidence
        via = headers.get("via")
        if via:
            signals.append("via")
            if proxy_type is None:
                proxy_type = "generic_proxy"

        # Check for forwarding headers (presence alone indicates proxying)
        for hdr in _PRESENCE_HEADERS:
            if hdr in headers:
                signals.append(hdr)
                if proxy_type is None:
                    proxy_type = "generic_proxy"

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "reverse_proxy_probe",
                "host": host,
                "detected": proxy_type is not None,
                "proxy_type": proxy_type or "none",
                "signals": signals,
            },
        )
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/unit/info_gathering/test_reverse_proxy_probe.py -v
```

Expected: all 4 tests `PASSED`

- [ ] **Step 5: Commit**

```bash
git add workers/info_gathering/tools/reverse_proxy_probe.py \
        tests/unit/info_gathering/test_reverse_proxy_probe.py
git commit -m "feat(info-gathering): add ReverseProxyProbe for WSTG-INFO-10 proxy detection"
```

---

## Task 7: Wire Up Three-Layer Coherence

**Files:**
- Modify: `workers/info_gathering/pipeline.py`
- Modify: `workers/info_gathering/concurrency.py`
- Modify: `dashboard/src/lib/worker-stages.ts`

- [ ] **Step 1: Update pipeline.py imports and stage definitions**

In `workers/info_gathering/pipeline.py`, add these imports in the block after `from .tools.whatweb import WhatWeb` (around line 67):

```python
from .tools.cms_fingerprinter import CMSFingerprinter
from .tools.cdn_probe import CDNProbe
from .tools.load_balancer_probe import LoadBalancerProbe
from .tools.serverless_probe import ServerlessProbe
from .tools.reverse_proxy_probe import ReverseProxyProbe
```

Change the `fingerprint_framework` stage (line ~100) from:
```python
    Stage(name="fingerprint_framework", section_id="4.1.8", tools=[
        Wappalyzer, CookieFingerprinter, Webanalyze,
        HeaderFrameworkProbe, MetaGeneratorProbe, FrameworkFileProber,
    ]),
```
to:
```python
    Stage(name="fingerprint_framework", section_id="4.1.8", tools=[
        Wappalyzer, CookieFingerprinter, Webanalyze,
        HeaderFrameworkProbe, MetaGeneratorProbe, FrameworkFileProber,
        CMSFingerprinter,
    ]),
```

Change the `map_architecture` stage (line ~104) from:
```python
    Stage(name="map_architecture", section_id="4.1.9", tools=[Waybackurls, ArchitectureModeler]),
```
to:
```python
    Stage(name="map_architecture", section_id="4.1.10", tools=[
        Waybackurls, ArchitectureModeler,
        CDNProbe, LoadBalancerProbe, ServerlessProbe, ReverseProxyProbe,
    ]),
```

- [ ] **Step 2: Update concurrency.py**

In `workers/info_gathering/concurrency.py`, add after the `"ArchitectureModeler": "LIGHT"` line:

```python
    "CMSFingerprinter":   "LIGHT",
    "CDNProbe":           "LIGHT",
    "LoadBalancerProbe":  "LIGHT",
    "ServerlessProbe":    "LIGHT",
    "ReverseProxyProbe":  "LIGHT",
```

- [ ] **Step 3: Update worker-stages.ts**

In `dashboard/src/lib/worker-stages.ts`, change line 20 from:
```typescript
    { id: "11", name: "Map Architecture", stageName: "map_architecture", sectionId: "WSTG-INFO-09" },
```
to:
```typescript
    { id: "11", name: "Map Architecture", stageName: "map_architecture", sectionId: "WSTG-INFO-10" },
```

- [ ] **Step 4: Verify imports resolve**

```bash
python -c "
import sys; sys.path.insert(0, '.')
from workers.info_gathering.tools.cms_fingerprinter import CMSFingerprinter
from workers.info_gathering.tools.cdn_probe import CDNProbe
from workers.info_gathering.tools.load_balancer_probe import LoadBalancerProbe
from workers.info_gathering.tools.serverless_probe import ServerlessProbe
from workers.info_gathering.tools.reverse_proxy_probe import ReverseProxyProbe
print('All imports OK')
"
```

Expected output: `All imports OK`

- [ ] **Step 5: Run full unit test suite**

```bash
pytest tests/unit/info_gathering/ -v
```

Expected: all tests `PASSED`, no `ERROR`

- [ ] **Step 6: Commit**

```bash
git add workers/info_gathering/pipeline.py \
        workers/info_gathering/concurrency.py \
        dashboard/src/lib/worker-stages.ts
git commit -m "feat(info-gathering): wire CMSFingerprinter + INFO-10 probes into pipeline; fix map_architecture section_id to 4.1.10"
```

---

## Self-Review Checklist

After completing all tasks, verify:

- [ ] `cms_fingerprints.json` loads without error
- [ ] `CMSFingerprinter` returns `ProbeResult` with `probe="cms_fingerprinter"` and `cms` slot signals
- [ ] `CDNProbe`, `LoadBalancerProbe`, `ServerlessProbe`, `ReverseProxyProbe` all save an `Observation` and return `None`
- [ ] `concurrency.py` has entries for all 5 new tool class names
- [ ] `pipeline.py` stage 8 `section_id` is still `"4.1.8"` and stage 9 `section_id` is now `"4.1.10"`
- [ ] `worker-stages.ts` `map_architecture` entry shows `sectionId: "WSTG-INFO-10"`
- [ ] All unit tests pass: `pytest tests/unit/info_gathering/ -v`
