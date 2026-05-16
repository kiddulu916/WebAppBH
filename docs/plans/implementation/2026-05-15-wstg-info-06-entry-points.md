# WSTG-INFO-06 Entry Points Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement full OWASP WSTG-INFO-06 coverage in the `info_gathering` pipeline by refactoring `FormMapper`, adding `WebSocketProber` and `EntryPointAggregator`, and splitting Stage 6 into a two-step discovery + aggregation sequence.

**Architecture:** Stage 6a (`identify_entry_points`) runs `FormMapper`, `Paramspider`, `Httpx`, and `WebSocketProber` concurrently. Stage 6b (`aggregate_entry_points`) runs `EntryPointAggregator` after Stage 6a is committed, so it can safely read everything Stage 6a wrote. Both stages share `section_id="4.1.6"`.

**Tech Stack:** Python asyncio, aiohttp, stdlib `html.parser`, SQLAlchemy async (lib_webbh), pytest + anyio, unittest.mock.

---

## File Map

| Action | Path |
|--------|------|
| Modify | `shared/lib_webbh/database.py` |
| Modify | `workers/info_gathering/tools/form_mapper.py` |
| Create | `workers/info_gathering/tools/websocket_prober.py` |
| Create | `workers/info_gathering/tools/entry_point_aggregator.py` |
| Modify | `workers/info_gathering/pipeline.py` |
| Modify | `workers/info_gathering/concurrency.py` |
| Create | `tests/test_wstg_info06_form_mapper.py` |
| Create | `tests/test_wstg_info06_websocket_prober.py` |
| Create | `tests/test_wstg_info06_entry_point_aggregator.py` |
| Create | `tests/test_wstg_info06_pipeline.py` |

---

## Task 1: Extend ASSET_TYPES

**Files:**
- Modify: `shared/lib_webbh/database.py:105-116`

- [ ] **Step 1: Write the failing test**

Create `tests/test_wstg_info06_pipeline.py`:

```python
"""Pipeline and concurrency registration tests for WSTG-INFO-06."""


def test_asset_types_includes_websocket_and_url():
    from lib_webbh.database import ASSET_TYPES
    assert "websocket" in ASSET_TYPES, "websocket missing from ASSET_TYPES"
    assert "url" in ASSET_TYPES, "url missing from ASSET_TYPES"
```

- [ ] **Step 2: Run test to verify it fails**

```
pytest tests/test_wstg_info06_pipeline.py::test_asset_types_includes_websocket_and_url -v
```

Expected: FAIL — `AssertionError: websocket missing from ASSET_TYPES`

- [ ] **Step 3: Add `"url"` and `"websocket"` to `ASSET_TYPES` in `database.py`**

Replace lines 105–116 in `shared/lib_webbh/database.py`:

```python
ASSET_TYPES = (
    "domain",          # Base / root domains
    "ip",              # IP addresses
    "subdomain",       # Subdomains discovered via enumeration
    "url",             # URLs discovered by crawlers and parameter spiders
    "websocket",       # WebSocket endpoints confirmed via active handshake
    "sensitive_file",  # Exposed files: .env, .sql, .bak, configs, backups, docs
    "directory",       # Interesting directory paths, admin panels, index-of pages
    "error",           # Error pages leaking stack traces, DB info, debug output
    "form",            # Pages with form fields / submit functionality
    "upload",          # Pages with file upload functionality
    "deadend",         # Low-value pages not worth further exploration
    "undetermined",    # Doesn't fit other categories; needs manual triage
)
```

- [ ] **Step 4: Run test to verify it passes**

```
pytest tests/test_wstg_info06_pipeline.py::test_asset_types_includes_websocket_and_url -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```
git add shared/lib_webbh/database.py tests/test_wstg_info06_pipeline.py
git commit -m "feat(db): add websocket and url to ASSET_TYPES"
```

---

## Task 2: Refactor FormMapper

Replaces the regex-based approach with stdlib `html.parser`. Adds hidden-field extraction and `Parameter` DB writes. Removes the hard URL cap.

**Files:**
- Modify: `workers/info_gathering/tools/form_mapper.py`
- Create: `tests/test_wstg_info06_form_mapper.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_wstg_info06_form_mapper.py`:

```python
"""Tests for enhanced FormMapper — WSTG-INFO-06."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.form_mapper import FormMapper, _FormParser


class TestFormParser:
    def test_extracts_action_and_method(self):
        p = _FormParser("https://example.com")
        p.feed('<form action="/login" method="POST"><input name="user"></form>')
        assert len(p.forms) == 1
        assert p.forms[0]["action"] == "https://example.com/login"
        assert p.forms[0]["method"] == "POST"

    def test_defaults_method_to_get_when_missing(self):
        p = _FormParser("https://example.com")
        p.feed('<form action="/"><input name="q"></form>')
        assert p.forms[0]["method"] == "GET"

    def test_flags_hidden_inputs_separately(self):
        p = _FormParser("https://example.com")
        p.feed(
            '<form>'
            '<input name="price" type="hidden" value="99">'
            '<input name="card">'
            '</form>'
        )
        assert "price" in p.forms[0]["hidden_fields"]
        assert "card" not in p.forms[0]["hidden_fields"]

    def test_collects_all_inputs_including_hidden(self):
        p = _FormParser("https://example.com")
        p.feed('<form><input name="price" type="hidden"><input name="card"></form>')
        names = [i["name"] for i in p.forms[0]["inputs"]]
        assert "price" in names
        assert "card" in names

    def test_skips_inputs_without_name_attribute(self):
        p = _FormParser("https://example.com")
        p.feed('<form><input type="submit" value="Go"><input name="email"></form>')
        names = [i["name"] for i in p.forms[0]["inputs"]]
        assert names == ["email"]

    def test_multiple_forms_collected(self):
        p = _FormParser("https://example.com")
        p.feed(
            '<form action="/a"><input name="x"></form>'
            '<form action="/b"><input name="y"></form>'
        )
        assert len(p.forms) == 2
        assert p.forms[0]["action"] == "https://example.com/a"
        assert p.forms[1]["action"] == "https://example.com/b"

    def test_handles_malformed_tag_without_raising(self):
        p = _FormParser("https://example.com")
        # Missing closing > on first input — parser must not raise
        p.feed('<form><input name="ok"<input name="also_ok"></form>')

    def test_textarea_and_select_collected(self):
        p = _FormParser("https://example.com")
        p.feed('<form><textarea name="msg"></textarea><select name="opt"></select></form>')
        names = [i["name"] for i in p.forms[0]["inputs"]]
        assert "msg" in names
        assert "opt" in names


class TestFormMapper:
    @pytest.mark.anyio
    async def test_no_target_kwarg_returns_zero(self):
        result = await FormMapper().execute(target_id=1)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_hidden_fields_present_in_observation_tech_stack(self):
        mapper = FormMapper()
        html = (
            '<form action="/pay">'
            '<input name="price" type="hidden" value="99">'
            '<input name="card">'
            '</form>'
        )
        target = MagicMock()
        target.base_domain = "example.com"
        captured_obs = {}

        async def capture(asset_id, tech_stack=None, **kw):
            if tech_stack:
                captured_obs.update(tech_stack)
            return 1

        with patch("workers.info_gathering.tools.form_mapper.get_session") as mock_gs, \
             patch.object(mapper, "_fetch_html", new_callable=AsyncMock, return_value=html), \
             patch.object(mapper, "save_asset", new_callable=AsyncMock, return_value=1), \
             patch.object(mapper, "save_observation", side_effect=capture), \
             patch.object(mapper, "_write_parameters", new_callable=AsyncMock):
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            await mapper.execute(target_id=1, target=target)

        assert "price" in captured_obs.get("hidden_fields", [])

    @pytest.mark.anyio
    async def test_write_parameters_called_for_found_form(self):
        mapper = FormMapper()
        html = '<form action="/s"><input name="a"><input name="b"></form>'
        target = MagicMock()
        target.base_domain = "example.com"

        with patch("workers.info_gathering.tools.form_mapper.get_session") as mock_gs, \
             patch.object(mapper, "_fetch_html", new_callable=AsyncMock, return_value=html), \
             patch.object(mapper, "save_asset", new_callable=AsyncMock, return_value=1), \
             patch.object(mapper, "save_observation", new_callable=AsyncMock, return_value=1), \
             patch.object(mapper, "_write_parameters", new_callable=AsyncMock) as mock_wp:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            result = await mapper.execute(target_id=1, target=target)

        assert result["found"] == 1
        assert mock_wp.call_count == 1

    @pytest.mark.anyio
    async def test_fetch_failure_continues_without_raising(self):
        mapper = FormMapper()
        target = MagicMock()
        target.base_domain = "example.com"

        with patch("workers.info_gathering.tools.form_mapper.get_session") as mock_gs, \
             patch.object(mapper, "_fetch_html", new_callable=AsyncMock, return_value=None):
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            result = await mapper.execute(target_id=1, target=target)

        assert result == {"found": 0}
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_wstg_info06_form_mapper.py -v
```

Expected: Multiple FAILs — `ImportError: cannot import name '_FormParser'` (and existing FormMapper has no `_FormParser`, no `_write_parameters`).

- [ ] **Step 3: Rewrite `form_mapper.py`**

Replace the entire contents of `workers/info_gathering/tools/form_mapper.py`:

```python
# workers/info_gathering/tools/form_mapper.py
"""FormMapper — discover HTML forms using stdlib html.parser; write Parameter rows."""

import aiohttp
from html.parser import HTMLParser
from urllib.parse import urljoin

from sqlalchemy import select

from lib_webbh import Asset, Parameter, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger


class _FormParser(HTMLParser):
    """Stateful HTML parser that collects all forms and their named inputs."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "form":
            self._current = {
                "action": urljoin(self.base_url, attr.get("action") or self.base_url),
                "method": (attr.get("method") or "GET").upper(),
                "inputs": [],
                "hidden_fields": [],
            }
        elif tag in ("input", "textarea", "select") and self._current is not None:
            name = attr.get("name")
            if not name:
                return
            input_type = attr.get("type", "text").lower()
            self._current["inputs"].append({
                "name": name,
                "type": input_type,
                "value": attr.get("value"),
            })
            if input_type == "hidden":
                self._current["hidden_fields"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


class FormMapper(InfoGatheringTool):
    """Discover and map HTML forms; write Parameter rows for all named inputs."""

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        if not target:
            return {"found": 0}

        rate_limiter = kwargs.get("rate_limiter")

        async with get_session() as session:
            rows = (await session.execute(
                select(Asset.asset_value, Asset.id).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                )
            )).all()

        # Always include the base domain; never cap the list
        urls = [(f"https://{target.base_domain}", None)] + [
            (row[0], row[1]) for row in rows
        ]

        saved = 0
        for url, existing_asset_id in urls:
            try:
                await self.acquire_rate_limit(rate_limiter)
                html = await self._fetch_html(url)
                if not html:
                    continue
                parser = _FormParser(base_url=url)
                parser.feed(html)
                if not parser.forms:
                    continue

                page_asset_id = existing_asset_id or await self.save_asset(
                    target_id, "form", url, "form_mapper",
                )
                if page_asset_id is None:
                    async with get_session() as session:
                        row = (await session.execute(
                            select(Asset.id).where(
                                Asset.target_id == target_id,
                                Asset.asset_value == url,
                            )
                        )).first()
                        page_asset_id = row[0] if row else None
                if page_asset_id is None:
                    continue

                for form in parser.forms:
                    await self.save_observation(
                        asset_id=page_asset_id,
                        tech_stack={
                            "_probe": "form_mapper",
                            "action": form["action"],
                            "method": form["method"],
                            "input_count": len(form["inputs"]),
                            "hidden_fields": form["hidden_fields"],
                        },
                    )
                    await self._write_parameters(page_asset_id, form)
                saved += 1
            except Exception as e:
                logger.warning(f"FormMapper failed on {url}: {e}")
                continue

        return {"found": saved}

    async def _fetch_html(self, url: str) -> str | None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except Exception as e:
            logger.warning(f"FormMapper fetch failed for {url}: {e}")
        return None

    async def _write_parameters(self, asset_id: int, form: dict) -> None:
        async with get_session() as session:
            for inp in form["inputs"]:
                name = inp.get("name")
                if not name:
                    continue
                existing = (await session.execute(
                    select(Parameter).where(
                        Parameter.asset_id == asset_id,
                        Parameter.param_name == name,
                    )
                )).scalar_one_or_none()
                if existing is not None:
                    continue
                session.add(Parameter(
                    asset_id=asset_id,
                    param_name=name,
                    param_value=inp.get("value"),
                    source_url=form["action"],
                ))
            await session.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_wstg_info06_form_mapper.py -v
```

Expected: All PASS

- [ ] **Step 5: Run full suite to check for regressions**

```
pytest tests/ -x -q
```

Expected: No failures introduced.

- [ ] **Step 6: Commit**

```
git add workers/info_gathering/tools/form_mapper.py tests/test_wstg_info06_form_mapper.py
git commit -m "feat(info-gathering): refactor FormMapper for WSTG-INFO-06 — html.parser, hidden fields, Parameter writes, no URL cap"
```

---

## Task 3: Implement WebSocketProber

**Files:**
- Create: `workers/info_gathering/tools/websocket_prober.py`
- Modify: `tests/test_wstg_info06_websocket_prober.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_wstg_info06_websocket_prober.py`:

```python
"""Tests for WebSocketProber — WSTG-INFO-06."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.websocket_prober import (
    WebSocketProber,
    WS_PATHS,
    _ws_upgrade_headers,
)


class TestWsUpgradeHeaders:
    def test_contains_all_required_ws_fields(self):
        h = _ws_upgrade_headers()
        assert h["Upgrade"] == "websocket"
        assert h["Connection"] == "Upgrade"
        assert h["Sec-WebSocket-Version"] == "13"
        assert "Sec-WebSocket-Key" in h

    def test_key_is_base64_encoded_16_bytes(self):
        import base64
        key = _ws_upgrade_headers()["Sec-WebSocket-Key"]
        decoded = base64.b64decode(key)
        assert len(decoded) == 16

    def test_key_differs_between_calls(self):
        k1 = _ws_upgrade_headers()["Sec-WebSocket-Key"]
        k2 = _ws_upgrade_headers()["Sec-WebSocket-Key"]
        assert k1 != k2


class TestWsPathWordlist:
    def test_contains_core_ws_paths(self):
        for path in ("/ws", "/socket", "/websocket", "/socket.io", "/chat", "/stream"):
            assert path in WS_PATHS

    def test_has_at_least_ten_paths(self):
        assert len(WS_PATHS) >= 10


class TestWebSocketProber:
    @pytest.mark.anyio
    async def test_missing_target_returns_zero(self):
        result = await WebSocketProber().execute(target_id=1)
        assert result == {"found": 0, "rejected": 0}

    @pytest.mark.anyio
    async def test_missing_asset_id_returns_zero(self):
        result = await WebSocketProber().execute(target_id=1, target=MagicMock())
        assert result == {"found": 0, "rejected": 0}

    @pytest.mark.anyio
    async def test_101_response_creates_websocket_asset_and_observation(self):
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_probe(session, url):
            return (101, True) if url == "https://example.com/ws" else (200, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "save_asset", new_callable=AsyncMock, return_value=10), \
             patch.object(prober, "_lookup_asset_id", new_callable=AsyncMock, return_value=10), \
             patch.object(prober, "save_observation", new_callable=AsyncMock, return_value=1) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(target_id=1, target=target, asset_id=5)

        prober.save_asset.assert_any_call(1, "websocket", "https://example.com/ws", "websocket_prober")
        assert result["found"] >= 1
        # Observation tech_stack should mark upgrade_accepted=True
        obs_call = next(
            c for c in mock_obs.call_args_list
            if c.kwargs.get("tech_stack", {}).get("upgrade_accepted")
        )
        assert obs_call.kwargs["tech_stack"]["path"] == "/ws"

    @pytest.mark.anyio
    async def test_403_writes_observation_but_no_asset(self):
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_probe(session, url):
            return (403, False) if url == "https://example.com/ws" else (200, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "save_asset", new_callable=AsyncMock) as mock_save, \
             patch.object(prober, "save_observation", new_callable=AsyncMock, return_value=1) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(target_id=1, target=target, asset_id=5)

        mock_save.assert_not_called()
        assert mock_obs.called
        rejected_call = next(
            c for c in mock_obs.call_args_list
            if c.kwargs.get("tech_stack", {}).get("upgrade_rejected")
        )
        assert rejected_call.kwargs["tech_stack"]["status"] == 403
        assert result["rejected"] >= 1

    @pytest.mark.anyio
    async def test_connection_error_skipped_no_db_writes(self):
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_probe(session, url):
            return (0, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "save_asset", new_callable=AsyncMock) as mock_save, \
             patch.object(prober, "save_observation", new_callable=AsyncMock) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(target_id=1, target=target, asset_id=5)

        mock_save.assert_not_called()
        mock_obs.assert_not_called()
        assert result == {"found": 0, "rejected": 0}
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_wstg_info06_websocket_prober.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'workers.info_gathering.tools.websocket_prober'`

- [ ] **Step 3: Create `websocket_prober.py`**

Create `workers/info_gathering/tools/websocket_prober.py`:

```python
# workers/info_gathering/tools/websocket_prober.py
"""WebSocketProber — detect WebSocket endpoints via active WS upgrade handshake."""

import base64
import os

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger

WS_PATHS = [
    "/ws", "/socket", "/websocket", "/socket.io",
    "/chat", "/live", "/stream", "/events",
    "/updates", "/notify", "/push", "/realtime", "/feed",
]


def _ws_upgrade_headers() -> dict[str, str]:
    key = base64.b64encode(os.urandom(16)).decode()
    return {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key,
    }


class WebSocketProber(InfoGatheringTool):
    """Probe base domain and all discovered subdomains for WebSocket endpoints."""

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or not asset_id:
            return {"found": 0, "rejected": 0}

        rate_limiter = kwargs.get("rate_limiter")

        async with get_session() as session:
            rows = (await session.execute(
                select(Asset.asset_value, Asset.id).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["subdomain", "domain"]),
                )
            )).all()

        hosts = [(target.base_domain, asset_id)] + [
            (row[0], row[1]) for row in rows
            if row[0] != target.base_domain
        ]

        confirmed = 0
        rejected = 0

        async with aiohttp.ClientSession() as http:
            for host, host_asset_id in hosts:
                for path in WS_PATHS:
                    url = f"https://{host}{path}"
                    await self.acquire_rate_limit(rate_limiter)
                    status, accepted = await self._probe(http, url)
                    if accepted:
                        ws_asset_id = await self.save_asset(
                            target_id, "websocket", url, "websocket_prober",
                        )
                        if ws_asset_id is None:
                            ws_asset_id = await self._lookup_asset_id(target_id, url)
                        if ws_asset_id:
                            await self.save_observation(
                                asset_id=ws_asset_id,
                                tech_stack={
                                    "_probe": "websocket_prober",
                                    "status": 101,
                                    "host": host,
                                    "path": path,
                                    "upgrade_accepted": True,
                                },
                            )
                        confirmed += 1
                    elif status in (400, 403):
                        await self.save_observation(
                            asset_id=host_asset_id,
                            tech_stack={
                                "_probe": "websocket_prober",
                                "status": status,
                                "host": host,
                                "path": path,
                                "upgrade_rejected": True,
                            },
                        )
                        rejected += 1

        return {"found": confirmed, "rejected": rejected}

    async def _probe(
        self, session: aiohttp.ClientSession, url: str,
    ) -> tuple[int, bool]:
        try:
            async with session.get(
                url,
                headers=_ws_upgrade_headers(),
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False,
            ) as resp:
                return resp.status, resp.status == 101
        except Exception:
            return 0, False

    async def _lookup_asset_id(self, target_id: int, url: str) -> int | None:
        async with get_session() as session:
            row = (await session.execute(
                select(Asset.id).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == url,
                    Asset.asset_type == "websocket",
                )
            )).first()
            return row[0] if row else None
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_wstg_info06_websocket_prober.py -v
```

Expected: All PASS

- [ ] **Step 5: Run full suite to check for regressions**

```
pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```
git add workers/info_gathering/tools/websocket_prober.py tests/test_wstg_info06_websocket_prober.py
git commit -m "feat(info-gathering): add WebSocketProber for WSTG-INFO-06 WS endpoint detection"
```

---

## Task 4: Implement EntryPointAggregator

**Files:**
- Create: `workers/info_gathering/tools/entry_point_aggregator.py`
- Create: `tests/test_wstg_info06_entry_point_aggregator.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_wstg_info06_entry_point_aggregator.py`:

```python
"""Tests for EntryPointAggregator — WSTG-INFO-06."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.entry_point_aggregator import EntryPointAggregator


class TestExtractHeaderData:
    def _make_resp(self, status: int, headers: dict) -> MagicMock:
        """Build a fake aiohttp response with dict-backed headers."""
        resp = MagicMock()
        resp.status = status

        class FakeHeaders:
            def __init__(self, data):
                self._d = {k.lower(): v for k, v in data.items()}
                self._raw = data

            def items(self):
                return self._raw.items()

            def getall(self, key, default=None):
                val = self._raw.get(key) or self._raw.get(key.lower())
                if val is None:
                    return default or []
                return [val] if isinstance(val, str) else val

            def get(self, key, default=None):
                return self._raw.get(key) or self._raw.get(key.lower()) or default

            def __iter__(self):
                return iter(self._raw)

            def __contains__(self, item):
                return item in self._raw or item.lower() in self._d

        resp.headers = FakeHeaders(headers)
        return resp

    def test_captures_set_cookie(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"Set-Cookie": "session=abc; HttpOnly"})
        result = agg._extract_header_data(resp)
        assert "session=abc; HttpOnly" in result["set_cookie"]

    def test_captures_x_prefixed_custom_headers(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"X-Debug": "false", "Content-Type": "text/html"})
        result = agg._extract_header_data(resp)
        assert "X-Debug" in result["custom_headers"]

    def test_captures_server_header(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"Server": "nginx/1.21"})
        result = agg._extract_header_data(resp)
        assert "Server" in result["custom_headers"]

    def test_auth_required_true_on_401(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(401, {})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is True

    def test_auth_required_true_on_403(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(403, {})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is True

    def test_auth_required_true_on_www_authenticate_header(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"WWW-Authenticate": "Basic realm=x"})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is True

    def test_auth_required_false_on_200_no_auth_header(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {"Content-Type": "text/html"})
        result = agg._extract_header_data(resp)
        assert result["auth_required"] is False

    def test_probe_key_present(self):
        agg = EntryPointAggregator()
        resp = self._make_resp(200, {})
        result = agg._extract_header_data(resp)
        assert result["_probe"] == "entry_point_aggregator"


class TestConsolidateQueryParams:
    @pytest.mark.anyio
    async def test_writes_parameter_rows_for_query_string(self):
        agg = EntryPointAggregator()
        asset = MagicMock()
        asset.id = 1
        asset.asset_value = "https://example.com/search?q=test&page=2"

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            # No existing params
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=None)
            sess.execute = AsyncMock(return_value=mock_result)

            written = await agg._consolidate_query_params(asset)

        assert written == 2
        assert sess.add.call_count == 2

    @pytest.mark.anyio
    async def test_skips_existing_parameters(self):
        agg = EntryPointAggregator()
        asset = MagicMock()
        asset.id = 1
        asset.asset_value = "https://example.com/search?q=test"

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=MagicMock())
            sess.execute = AsyncMock(return_value=mock_result)

            written = await agg._consolidate_query_params(asset)

        assert written == 0
        sess.add.assert_not_called()

    @pytest.mark.anyio
    async def test_url_with_no_query_string_returns_zero(self):
        agg = EntryPointAggregator()
        asset = MagicMock()
        asset.id = 1
        asset.asset_value = "https://example.com/about"
        written = await agg._consolidate_query_params(asset)
        assert written == 0


class TestEntryPointAggregatorExecute:
    @pytest.mark.anyio
    async def test_observation_written_per_asset(self):
        agg = EntryPointAggregator()

        fake_asset = MagicMock()
        fake_asset.id = 7
        fake_asset.asset_value = "https://example.com/login"
        fake_asset.source_tool = "katana"

        fake_obs_data = {
            "_probe": "entry_point_aggregator",
            "custom_headers": {"X-Frame-Options": "DENY"},
            "set_cookie": ["session=x"],
            "auth_required": False,
            "methods_allowed": [],
            "status_code": 200,
        }

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs, \
             patch.object(agg, "_capture_headers", new_callable=AsyncMock, return_value=fake_obs_data), \
             patch.object(agg, "_consolidate_query_params", new_callable=AsyncMock, return_value=0), \
             patch.object(agg, "save_observation", new_callable=AsyncMock, return_value=1) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_scalars = AsyncMock()
            mock_scalars.all = MagicMock(return_value=[fake_asset])
            mock_exec_result = AsyncMock()
            mock_exec_result.scalars = MagicMock(return_value=mock_scalars)
            sess.execute = AsyncMock(return_value=mock_exec_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await agg.execute(target_id=1)

        assert result["found"] == 1
        mock_obs.assert_called_once()
        assert mock_obs.call_args.kwargs["asset_id"] == 7

    @pytest.mark.anyio
    async def test_paramspider_assets_trigger_param_consolidation(self):
        agg = EntryPointAggregator()

        paramspider_asset = MagicMock()
        paramspider_asset.id = 3
        paramspider_asset.asset_value = "https://example.com/search?q=test"
        paramspider_asset.source_tool = "paramspider"

        with patch("workers.info_gathering.tools.entry_point_aggregator.get_session") as mock_gs, \
             patch.object(agg, "_capture_headers", new_callable=AsyncMock, return_value=None), \
             patch.object(agg, "_consolidate_query_params", new_callable=AsyncMock, return_value=1) as mock_cons, \
             patch.object(agg, "save_observation", new_callable=AsyncMock, return_value=1), \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_scalars = AsyncMock()
            mock_scalars.all = MagicMock(return_value=[paramspider_asset])
            mock_exec_result = AsyncMock()
            mock_exec_result.scalars = MagicMock(return_value=mock_scalars)
            sess.execute = AsyncMock(return_value=mock_exec_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await agg.execute(target_id=1)

        mock_cons.assert_called_once_with(paramspider_asset)
        assert result["parameters"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_wstg_info06_entry_point_aggregator.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'workers.info_gathering.tools.entry_point_aggregator'`

- [ ] **Step 3: Create `entry_point_aggregator.py`**

Create `workers/info_gathering/tools/entry_point_aggregator.py`:

```python
# workers/info_gathering/tools/entry_point_aggregator.py
"""EntryPointAggregator — per-endpoint response header capture + parameter consolidation."""

from urllib.parse import parse_qsl, urlparse

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, Parameter, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger

_CUSTOM_PREFIXES = ("x-", "cf-")
_NAMED_HEADERS = frozenset({"server", "content-type", "allow", "www-authenticate"})


class EntryPointAggregator(InfoGatheringTool):
    """Fetch every discovered url/form endpoint; record headers + consolidate params."""

    async def execute(self, target_id: int, **kwargs) -> dict:
        rate_limiter = kwargs.get("rate_limiter")

        async with get_session() as session:
            assets = (await session.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["url", "form"]),
                )
            )).scalars().all()

        obs_count = 0
        param_count = 0

        async with aiohttp.ClientSession() as http:
            for asset in assets:
                await self.acquire_rate_limit(rate_limiter)
                obs_data = await self._capture_headers(http, asset.asset_value)
                if obs_data:
                    await self.save_observation(
                        asset_id=asset.id,
                        tech_stack=obs_data,
                        status_code=obs_data.get("status_code"),
                    )
                    obs_count += 1
                if asset.source_tool == "paramspider":
                    written = await self._consolidate_query_params(asset)
                    param_count += written

        return {"found": obs_count, "parameters": param_count}

    async def _capture_headers(
        self, session: aiohttp.ClientSession, url: str,
    ) -> dict | None:
        for method_name in ("head", "get"):
            try:
                method = getattr(session, method_name)
                async with method(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    if method_name == "head" and resp.status == 405:
                        continue
                    return self._extract_header_data(resp)
            except Exception:
                continue
        logger.warning(f"EntryPointAggregator: could not fetch {url}")
        return None

    def _extract_header_data(self, resp: aiohttp.ClientResponse) -> dict:
        headers = resp.headers
        custom = {
            k: v for k, v in headers.items()
            if k.lower().startswith(_CUSTOM_PREFIXES)
            or k.lower() in _NAMED_HEADERS
        }
        cookies = list(headers.getall("Set-Cookie", []))
        auth_required = (
            resp.status in (401, 403)
            or "www-authenticate" in {k.lower() for k in headers}
        )
        allow = headers.get("Allow", "")
        methods = [m.strip() for m in allow.split(",")] if allow else []
        return {
            "_probe": "entry_point_aggregator",
            "custom_headers": custom,
            "set_cookie": cookies,
            "auth_required": auth_required,
            "methods_allowed": methods,
            "status_code": resp.status,
        }

    async def _consolidate_query_params(self, asset: Asset) -> int:
        params = parse_qsl(urlparse(asset.asset_value).query, keep_blank_values=True)
        if not params:
            return 0
        written = 0
        async with get_session() as session:
            for name, value in params:
                existing = (await session.execute(
                    select(Parameter).where(
                        Parameter.asset_id == asset.id,
                        Parameter.param_name == name,
                    )
                )).scalar_one_or_none()
                if existing is not None:
                    continue
                session.add(Parameter(
                    asset_id=asset.id,
                    param_name=name,
                    param_value=value or None,
                    source_url=asset.asset_value,
                ))
                written += 1
            await session.commit()
        return written
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_wstg_info06_entry_point_aggregator.py -v
```

Expected: All PASS

- [ ] **Step 5: Run full suite to check for regressions**

```
pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```
git add workers/info_gathering/tools/entry_point_aggregator.py tests/test_wstg_info06_entry_point_aggregator.py
git commit -m "feat(info-gathering): add EntryPointAggregator for WSTG-INFO-06 header capture and param consolidation"
```

---

## Task 5: Wire Pipeline and Concurrency

**Files:**
- Modify: `workers/info_gathering/pipeline.py`
- Modify: `workers/info_gathering/concurrency.py`
- Modify: `tests/test_wstg_info06_pipeline.py`

- [ ] **Step 1: Add pipeline and concurrency tests**

Append to `tests/test_wstg_info06_pipeline.py`:

```python
def test_identify_entry_points_stage_contains_websocket_prober():
    from workers.info_gathering.pipeline import STAGES
    from workers.info_gathering.tools.websocket_prober import WebSocketProber
    stage = next(s for s in STAGES if s.name == "identify_entry_points")
    assert WebSocketProber in stage.tools


def test_aggregate_entry_points_stage_exists_after_identify():
    from workers.info_gathering.pipeline import STAGES
    names = [s.name for s in STAGES]
    id_idx = names.index("identify_entry_points")
    agg_idx = names.index("aggregate_entry_points")
    assert agg_idx == id_idx + 1


def test_aggregate_entry_points_has_entry_point_aggregator():
    from workers.info_gathering.pipeline import STAGES
    from workers.info_gathering.tools.entry_point_aggregator import EntryPointAggregator
    stage = next(s for s in STAGES if s.name == "aggregate_entry_points")
    assert stage.tools == [EntryPointAggregator]


def test_aggregate_entry_points_shares_section_id_with_identify():
    from workers.info_gathering.pipeline import STAGES
    id_stage = next(s for s in STAGES if s.name == "identify_entry_points")
    agg_stage = next(s for s in STAGES if s.name == "aggregate_entry_points")
    assert id_stage.section_id == agg_stage.section_id == "4.1.6"


def test_new_tools_registered_as_light_in_concurrency():
    from workers.info_gathering.concurrency import TOOL_WEIGHTS
    assert TOOL_WEIGHTS["WebSocketProber"] == "LIGHT"
    assert TOOL_WEIGHTS["EntryPointAggregator"] == "LIGHT"
```

- [ ] **Step 2: Run new tests to verify they fail**

```
pytest tests/test_wstg_info06_pipeline.py -v
```

Expected: FAIL — `StopIteration` (WebSocketProber not in stage) and `KeyError` (missing concurrency entries).

- [ ] **Step 3: Update `pipeline.py`**

In `workers/info_gathering/pipeline.py`, add two imports alongside the existing tool imports (around line 23–64):

```python
from .tools.entry_point_aggregator import EntryPointAggregator
from .tools.websocket_prober import WebSocketProber
```

Then replace the existing `identify_entry_points` Stage entry in the `STAGES` list:

```python
    Stage(name="identify_entry_points",  section_id="4.1.6",
          tools=[FormMapper, Paramspider, Httpx, WebSocketProber]),
    Stage(name="aggregate_entry_points", section_id="4.1.6",
          tools=[EntryPointAggregator]),
```

(The old single-line entry was `Stage(name="identify_entry_points", section_id="4.1.6", tools=[FormMapper, Paramspider, Httpx])` — replace it with the two lines above.)

- [ ] **Step 4: Update `concurrency.py`**

In `workers/info_gathering/concurrency.py`, add these two entries to `TOOL_WEIGHTS` alongside the existing entries:

```python
    "WebSocketProber":      "LIGHT",
    "EntryPointAggregator": "LIGHT",
```

- [ ] **Step 5: Run all pipeline tests**

```
pytest tests/test_wstg_info06_pipeline.py -v
```

Expected: All PASS

- [ ] **Step 6: Run full test suite**

```
pytest tests/ -x -q
```

Expected: All PASS — no regressions.

- [ ] **Step 7: Commit**

```
git add workers/info_gathering/pipeline.py workers/info_gathering/concurrency.py tests/test_wstg_info06_pipeline.py
git commit -m "feat(info-gathering): wire WebSocketProber + EntryPointAggregator into Stage 6 pipeline"
```
