# WSTG-INFO-03 Metafiles Stage 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand Stage 3 of the `info_gathering` pipeline to fully cover WSTG-INFO-03 by rewriting `MetafileParser`, adding `MetaTagAnalyzer`, and wiring both into `pipeline.py`.

**Architecture:** `MetafileParser` runs a two-phase execute — first fetch `robots.txt` to collect declared `Sitemap:` refs, then concurrently fetch sitemap, security.txt, humans.txt, and probe `.well-known/` paths. `MetaTagAnalyzer` fetches the root HTML page and extracts `<meta>` tags from `<head>`. Both tools write `Observation` records with a semantic tag taxonomy (`intel:*`, `candidate:*`) that downstream workers query to consume the intel. No `Vulnerability` records are emitted by Stage 3.

**Tech Stack:** Python asyncio, aiohttp, stdlib `html.parser` and `re`, pytest + pytest-anyio + unittest.mock

---

## File Map

| File | Action |
|------|--------|
| `tests/test_info_gathering_metafiles.py` | Create — all Stage 3 tests |
| `workers/info_gathering/tools/metafile_parser.py` | Full rewrite |
| `workers/info_gathering/tools/meta_tag_analyzer.py` | New file |
| `workers/info_gathering/pipeline.py` | Add import + update Stage 3 tools list |

---

## Tag Taxonomy Reference

Used in every `Observation.tech_stack` payload written by Stage 3 tools.

**Intel tags** (passive facts):
- `intel:hidden-path` — URL path disclosed by a metafile, not linked from public surface
- `intel:tech-stack` — Technology name, version, or framework hint
- `intel:employee-pii` — Team name, role, or contact info from humans.txt / security.txt
- `intel:security-contact` — Security disclosure contact from security.txt
- `intel:site-structure` — Structural info (OG URLs, sitemap hierarchy)
- `intel:social-account` — Social media handle from meta tags
- `intel:crawler-hint` — Robots META directive or User-Agent hint

**Candidate tags** (action hints for downstream workers):
- `candidate:forced-browsing` — Path should be probed directly
- `candidate:authn-bypass` — Path looks like auth-protected area worth testing
- `candidate:entry-point` — URL from sitemap, candidate for input/param testing
- `candidate:version-disclosure` — Tech version hinted in meta tags

---

## Task 1: Create test file — MetafileParser pure parser tests

**Files:**
- Create: `tests/test_info_gathering_metafiles.py`

These tests cover the pure string-in / dict-out parser methods. No HTTP or DB mocking needed. Write these first — they will all fail because the new implementation doesn't exist yet.

- [ ] **Step 1: Create the test file**

```python
# tests/test_info_gathering_metafiles.py
"""Tests for WSTG-INFO-03 Stage 3: MetafileParser and MetaTagAnalyzer."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.metafile_parser import MetafileParser
from workers.info_gathering.tools.meta_tag_analyzer import MetaTagAnalyzer


# ---------------------------------------------------------------------------
# MetafileParser — pure parser tests
# ---------------------------------------------------------------------------

class TestParseRobots:
    def setup_method(self):
        self.p = MetafileParser()

    def test_disallow_paths_extracted(self):
        content = "User-agent: *\nDisallow: /admin\nDisallow: /private\n"
        result = self.p._parse_robots(content)
        assert result["disallow"] == ["/admin", "/private"]

    def test_allow_paths_extracted(self):
        content = "User-agent: *\nAllow: /public\nDisallow: /private\n"
        result = self.p._parse_robots(content)
        assert result["allow"] == ["/public"]

    def test_wildcard_user_agent_excluded(self):
        content = "User-agent: Googlebot\nUser-agent: *\nDisallow: /admin\n"
        result = self.p._parse_robots(content)
        assert "Googlebot" in result["user_agents"]
        assert "*" not in result["user_agents"]

    def test_sitemap_refs_extracted(self):
        content = "User-agent: *\nSitemap: https://example.com/sitemap.xml\n"
        result = self.p._parse_robots(content)
        assert result["sitemaps"] == ["https://example.com/sitemap.xml"]

    def test_empty_disallow_lines_skipped(self):
        content = "User-agent: *\nDisallow:\nDisallow: /admin\n"
        result = self.p._parse_robots(content)
        assert result["disallow"] == ["/admin"]


class TestTagsForPath:
    def setup_method(self):
        self.p = MetafileParser()

    def test_admin_prefix_gets_candidate_tags(self):
        tags = self.p._tags_for_path("/admin/users")
        assert "intel:hidden-path" in tags
        assert "candidate:forced-browsing" in tags
        assert "candidate:authn-bypass" in tags

    def test_api_prefix_gets_candidate_tags(self):
        tags = self.p._tags_for_path("/api/v2/internal")
        assert "candidate:forced-browsing" in tags

    def test_non_sensitive_path_only_hidden_path_tag(self):
        tags = self.p._tags_for_path("/blog/posts")
        assert tags == ["intel:hidden-path"]

    def test_case_insensitive_prefix_match(self):
        tags = self.p._tags_for_path("/ADMIN/panel")
        assert "candidate:forced-browsing" in tags

    def test_partial_prefix_not_matched(self):
        # /administrator should not match /admin prefix detection ambiguity
        # but /admin IS a prefix of /administrator so it should match
        tags = self.p._tags_for_path("/administrator")
        assert "candidate:forced-browsing" in tags


class TestParseSitemap:
    def setup_method(self):
        self.p = MetafileParser()

    def test_loc_urls_extracted(self):
        content = "<urlset><url><loc>https://example.com/page1</loc></url></urlset>"
        result = self.p._parse_sitemap(content)
        assert result["urls"] == ["https://example.com/page1"]
        assert result["nested_sitemaps"] == []

    def test_nested_sitemap_index_extracted(self):
        content = (
            "<sitemapindex>"
            "<sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>"
            "</sitemapindex>"
        )
        result = self.p._parse_sitemap(content)
        assert result["nested_sitemaps"] == ["https://example.com/sitemap-posts.xml"]
        assert result["urls"] == []

    def test_nested_sitemap_locs_excluded_from_urls(self):
        """<loc> inside <sitemap> blocks must not appear in urls[]."""
        content = (
            "<sitemapindex>"
            "<sitemap><loc>https://example.com/sub.xml</loc></sitemap>"
            "<url><loc>https://example.com/page</loc></url>"
            "</sitemapindex>"
        )
        result = self.p._parse_sitemap(content)
        assert "https://example.com/sub.xml" not in result["urls"]
        assert "https://example.com/page" in result["urls"]

    def test_nested_sitemap_capped_at_three(self):
        locs = "".join(
            f"<sitemap><loc>https://example.com/s{i}.xml</loc></sitemap>"
            for i in range(5)
        )
        content = f"<sitemapindex>{locs}</sitemapindex>"
        result = self.p._parse_sitemap(content)
        assert len(result["nested_sitemaps"]) == 3


class TestParseSecurityTxt:
    def setup_method(self):
        self.p = MetafileParser()

    def test_contact_extracted(self):
        content = "Contact: mailto:security@example.com\n"
        result = self.p._parse_security_txt(content)
        assert result["contacts"] == ["mailto:security@example.com"]

    def test_policy_extracted(self):
        content = "Policy: https://example.com/security-policy\n"
        result = self.p._parse_security_txt(content)
        assert result["policies"] == ["https://example.com/security-policy"]

    def test_hiring_extracted(self):
        content = "Hiring: https://example.com/jobs\n"
        result = self.p._parse_security_txt(content)
        assert result["hiring"] == ["https://example.com/jobs"]

    def test_expires_extracted_as_scalar(self):
        content = "Expires: 2026-12-31T00:00:00Z\n"
        result = self.p._parse_security_txt(content)
        assert result["expires"] == "2026-12-31T00:00:00Z"

    def test_encryption_extracted(self):
        content = "Encryption: https://example.com/pgp-key.txt\n"
        result = self.p._parse_security_txt(content)
        assert result["encryption"] == ["https://example.com/pgp-key.txt"]

    def test_missing_fields_return_empty(self):
        content = "Contact: mailto:sec@example.com\n"
        result = self.p._parse_security_txt(content)
        assert result["hiring"] == []
        assert result["expires"] is None


class TestParseHumansTxt:
    def setup_method(self):
        self.p = MetafileParser()

    def test_team_section_parsed(self):
        content = "/* TEAM */\nName: Alice Smith\nRole: Lead Developer\n"
        result = self.p._parse_humans_txt(content)
        assert any(e["field"] == "Name" and e["value"] == "Alice Smith" for e in result["team"])
        assert any(e["field"] == "Role" and e["value"] == "Lead Developer" for e in result["team"])

    def test_site_section_becomes_tech_credits(self):
        content = "/* SITE */\nWordPress 6.4\njQuery 3.7\n"
        result = self.p._parse_humans_txt(content)
        assert "WordPress 6.4" in result["tech_credits"]
        assert "jQuery 3.7" in result["tech_credits"]

    def test_technology_section_becomes_tech_credits(self):
        content = "/* TECHNOLOGY */\nReact 18.2\n"
        result = self.p._parse_humans_txt(content)
        assert "React 18.2" in result["tech_credits"]

    def test_team_lines_without_colon_skipped(self):
        content = "/* TEAM */\nAlice Smith\nRole: Dev\n"
        result = self.p._parse_humans_txt(content)
        assert not any(e["field"] == "Alice Smith" for e in result["team"])

    def test_empty_content_returns_empty_structures(self):
        result = self.p._parse_humans_txt("")
        assert result["team"] == []
        assert result["tech_credits"] == []
```

- [ ] **Step 2: Run the tests — confirm they all fail**

```
pytest tests/test_info_gathering_metafiles.py -v -k "TestParseRobots or TestTagsForPath or TestParseSitemap or TestParseSecurityTxt or TestParseHumansTxt"
```

Expected: `ImportError` or `AttributeError` — the new parser methods don't exist yet.

---

## Task 2: Write MetafileParser execute() behavior tests

**Files:**
- Modify: `tests/test_info_gathering_metafiles.py`

These tests cover the `execute()` method. They patch `_get()` (the internal HTTP helper) to control responses without real HTTP, and patch `save_observation` to assert what gets written. All will fail until Task 3.

- [ ] **Step 1: Append execute() tests to the test file**

```python
# Append to tests/test_info_gathering_metafiles.py

# ---------------------------------------------------------------------------
# MetafileParser — execute() behavior tests
# ---------------------------------------------------------------------------

class TestMetafileParserExecute:
    @pytest.mark.anyio
    async def test_sensitive_disallow_emits_candidate_tags(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if url.endswith("/robots.txt"):
                return 200, "User-agent: *\nDisallow: /admin\n"
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target, host="example.com")

        stacks = [c.kwargs["tech_stack"] for c in mock_save.call_args_list]
        admin_obs = [s for s in stacks if s.get("data", {}).get("path") == "/admin"]
        assert len(admin_obs) == 1
        assert "candidate:forced-browsing" in admin_obs[0]["tags"]
        assert "candidate:authn-bypass" in admin_obs[0]["tags"]

    @pytest.mark.anyio
    async def test_non_sensitive_disallow_only_hidden_path_tag(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if url.endswith("/robots.txt"):
                return 200, "User-agent: *\nDisallow: /blog\n"
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        stacks = [c.kwargs["tech_stack"] for c in mock_save.call_args_list]
        blog_obs = [s for s in stacks if s.get("data", {}).get("path") == "/blog"]
        assert len(blog_obs) == 1
        assert blog_obs[0]["tags"] == ["intel:hidden-path"]

    @pytest.mark.anyio
    async def test_all_404s_write_no_observations(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        assert mock_save.call_count == 0

    @pytest.mark.anyio
    async def test_security_txt_uses_well_known_path_first(self):
        """When both /.well-known/security.txt and /security.txt respond, only one obs written."""
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if "security.txt" in url:
                return 200, "Contact: mailto:sec@example.com\n"
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        security_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "security_txt"
        ]
        assert len(security_obs) == 1
        assert "intel:security-contact" in security_obs[0]["tags"]

    @pytest.mark.anyio
    async def test_security_txt_with_hiring_adds_employee_pii_tag(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if "security.txt" in url:
                return 200, "Contact: mailto:sec@example.com\nHiring: https://example.com/jobs\n"
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        security_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "security_txt"
        ]
        assert len(security_obs) == 1
        assert "intel:employee-pii" in security_obs[0]["tags"]

    @pytest.mark.anyio
    async def test_sitemap_batched_into_50_url_chunks(self):
        """120 URLs → 3 observations (50 + 50 + 20)."""
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        urls_xml = "".join(
            f"<url><loc>https://example.com/p{i}</loc></url>" for i in range(120)
        )
        sitemap_body = f"<urlset>{urls_xml}</urlset>"

        async def fake_get(session, url, rate_limiter=None):
            if url.endswith("/sitemap.xml"):
                return 200, sitemap_body
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        sitemap_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "sitemap_xml"
        ]
        assert len(sitemap_obs) == 3
        assert len(sitemap_obs[0]["data"]["urls"]) == 50
        assert len(sitemap_obs[2]["data"]["urls"]) == 20

    @pytest.mark.anyio
    async def test_robots_sitemap_ref_fed_to_sitemap_fetcher(self):
        """Sitemap: https://example.com/news.xml in robots.txt must be fetched."""
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if url.endswith("/robots.txt"):
                return 200, "Sitemap: https://example.com/news.xml\n"
            if url.endswith("/news.xml"):
                return 200, "<urlset><url><loc>https://example.com/news/1</loc></url></urlset>"
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        sitemap_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "sitemap_xml"
        ]
        all_urls = [u for obs in sitemap_obs for u in obs["data"]["urls"]]
        assert "https://example.com/news/1" in all_urls

    @pytest.mark.anyio
    async def test_humans_txt_team_emits_employee_pii_tag(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if url.endswith("/humans.txt"):
                return 200, "/* TEAM */\nName: Alice Smith\nRole: Dev\n"
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        humans_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "humans_txt"
        ]
        assert len(humans_obs) == 1
        assert "intel:employee-pii" in humans_obs[0]["tags"]

    @pytest.mark.anyio
    async def test_humans_txt_no_team_no_tech_skipped(self):
        """humans.txt with neither TEAM nor SITE/TECHNOLOGY section → no observation."""
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if url.endswith("/humans.txt"):
                return 200, "/* THANKS */\nOpenSource\n"
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        humans_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "humans_txt"
        ]
        assert len(humans_obs) == 0

    @pytest.mark.anyio
    async def test_well_known_auth_path_gets_authn_bypass_tag(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if "openid-configuration" in url:
                return 200, '{"issuer":"https://example.com"}'
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        wk_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "well_known_probe"
        ]
        assert any("candidate:authn-bypass" in obs["tags"] for obs in wk_obs)

    @pytest.mark.anyio
    async def test_well_known_non_auth_path_no_authn_bypass_tag(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_get(session, url, rate_limiter=None):
            if "apple-app-site-association" in url:
                return 200, '{"applinks":{}}'
            return 404, ""

        with patch.object(tool, "_get", side_effect=fake_get), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        wk_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("source") == "well_known_probe"
        ]
        assert len(wk_obs) == 1
        assert "candidate:authn-bypass" not in wk_obs[0]["tags"]
        assert "intel:hidden-path" in wk_obs[0]["tags"]

    @pytest.mark.anyio
    async def test_missing_asset_id_returns_early(self):
        tool = MetafileParser()
        target = MagicMock()
        target.base_domain = "example.com"

        with patch.object(tool, "_get", new_callable=AsyncMock) as mock_get:
            await tool.execute(target_id=1, asset_id=None, target=target)

        mock_get.assert_not_called()
```

- [ ] **Step 2: Run these new tests — confirm they fail**

```
pytest tests/test_info_gathering_metafiles.py -v -k "TestMetafileParserExecute"
```

Expected: `ImportError` or `AttributeError` — implementation doesn't exist yet.

---

## Task 3: Rewrite MetafileParser

**Files:**
- Modify: `workers/info_gathering/tools/metafile_parser.py`

Full rewrite. The key structural choices:
- Two-phase `execute()`: fetch `robots.txt` first (returns its declared `Sitemap:` refs), then run remaining 4 fetches concurrently, passing the sitemap refs into `_fetch_sitemap`.
- `_get()` is a single internal HTTP helper — all fetch methods call it, making the whole tool mockable via `patch.object(tool, "_get", ...)` in tests.
- `save_observation` called with `asset_id=` keyword (fixes the existing bug).

- [ ] **Step 1: Replace the entire file**

```python
# workers/info_gathering/tools/metafile_parser.py
"""MetafileParser — WSTG-INFO-03: review webserver metafiles for information leakage."""

import asyncio
import re

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool

_SENSITIVE_PREFIXES = (
    "/admin", "/api", "/internal", "/config", "/backup",
    "/staging", "/dev", "/test", "/dashboard", "/manage",
    "/private", "/.git", "/.env",
)

_WELL_KNOWN_PATHS = [
    "openid-configuration",
    "oauth-authorization-server",
    "webfinger",
    "change-password",
    "mta-sts.txt",
    "dmarc",
    "pki-validation",
    "apple-app-site-association",
    "assetlinks.json",
    "nodeinfo",
    "host-meta",
    "caldav",
    "carddav",
]

_WELL_KNOWN_AUTH = frozenset({
    "openid-configuration",
    "oauth-authorization-server",
    "change-password",
    "webfinger",
})

_SITEMAP_URL_CAP = 500
_SITEMAP_BATCH_SIZE = 50
_SITEMAP_CHILD_CAP = 3


class MetafileParser(InfoGatheringTool):
    """Parse robots.txt, sitemap.xml, security.txt, humans.txt, and .well-known/ endpoints."""

    async def execute(self, target_id: int, **kwargs) -> None:
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or asset_id is None:
            return

        host = kwargs.get("host") or target.base_domain
        base_url = f"https://{host}"
        rate_limiter = kwargs.get("rate_limiter")

        async with aiohttp.ClientSession() as session:
            # Phase 1: robots.txt first — returns declared Sitemap: refs
            robots_sitemaps = await self._fetch_robots(
                session, base_url, target_id, asset_id, rate_limiter
            )

            # Phase 2: remaining fetches concurrently
            await asyncio.gather(
                self._fetch_sitemap(
                    session, base_url, target_id, asset_id, rate_limiter,
                    extra_urls=robots_sitemaps,
                ),
                self._fetch_security_txt(session, base_url, target_id, asset_id, rate_limiter),
                self._fetch_humans_txt(session, base_url, target_id, asset_id, rate_limiter),
                self._probe_well_known(session, base_url, target_id, asset_id, rate_limiter),
                return_exceptions=True,
            )

    async def _get(
        self, session: aiohttp.ClientSession, url: str, rate_limiter=None
    ) -> tuple[int, str] | None:
        """GET url; return (status, body_text) or None on connection error."""
        await self.acquire_rate_limit(rate_limiter)
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="replace") if resp.status == 200 else ""
                return resp.status, body
        except Exception:
            return None

    # ------------------------------------------------------------------ robots
    async def _fetch_robots(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> list[str]:
        """Fetch robots.txt, write per-path observations, return declared Sitemap: URLs."""
        result = await self._get(session, f"{base_url}/robots.txt", rate_limiter)
        if not result or result[0] != 200:
            return []

        _, content = result
        parsed = self._parse_robots(content)

        for path in parsed["disallow"]:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "robots_txt",
                    "intel_type": "hidden_path",
                    "tags": self._tags_for_path(path),
                    "data": {"path": path, "context": "Disallow"},
                },
            )

        if parsed["user_agents"] or parsed["allow"]:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "robots_txt",
                    "intel_type": "hidden_path",
                    "tags": ["intel:crawler-hint"],
                    "data": {
                        "user_agents": parsed["user_agents"],
                        "allow": parsed["allow"],
                    },
                },
            )

        return parsed["sitemaps"]

    # ------------------------------------------------------------------ sitemap
    async def _fetch_sitemap(
        self, session, base_url, target_id, asset_id, rate_limiter,
        extra_urls: list[str] | None = None,
    ) -> None:
        urls_to_fetch = [f"{base_url}/sitemap.xml"]
        if extra_urls:
            urls_to_fetch += [u for u in extra_urls if u not in urls_to_fetch]

        all_urls: list[str] = []
        child_count = 0

        for sitemap_url in urls_to_fetch:
            result = await self._get(session, sitemap_url, rate_limiter)
            if not result or result[0] != 200:
                continue
            parsed = self._parse_sitemap(result[1])
            all_urls.extend(parsed["urls"])

            for child_url in parsed["nested_sitemaps"]:
                if child_count >= _SITEMAP_CHILD_CAP:
                    break
                child = await self._get(session, child_url, rate_limiter)
                if child and child[0] == 200:
                    all_urls.extend(self._parse_sitemap(child[1])["urls"])
                    child_count += 1

            if len(all_urls) >= _SITEMAP_URL_CAP:
                break

        all_urls = list(dict.fromkeys(all_urls))[:_SITEMAP_URL_CAP]
        if not all_urls:
            return

        for batch_num, i in enumerate(range(0, len(all_urls), _SITEMAP_BATCH_SIZE)):
            batch = all_urls[i : i + _SITEMAP_BATCH_SIZE]
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "sitemap_xml",
                    "intel_type": "sitemap_url",
                    "tags": ["candidate:entry-point", "intel:site-structure"],
                    "data": {"urls": batch, "batch": batch_num},
                },
            )

    # ------------------------------------------------------------------ security.txt
    async def _fetch_security_txt(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> None:
        for path in ("/.well-known/security.txt", "/security.txt"):
            result = await self._get(session, f"{base_url}{path}", rate_limiter)
            if not result or result[0] != 200:
                continue
            parsed = self._parse_security_txt(result[1])
            if not any(v for v in parsed.values() if v):
                return
            tags = ["intel:security-contact"]
            if parsed.get("hiring"):
                tags.append("intel:employee-pii")
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "security_txt",
                    "intel_type": "security_contact",
                    "tags": tags,
                    "data": parsed,
                },
            )
            return  # stop at first 200 (prefers /.well-known/)

    # ------------------------------------------------------------------ humans.txt
    async def _fetch_humans_txt(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> None:
        result = await self._get(session, f"{base_url}/humans.txt", rate_limiter)
        if not result or result[0] != 200:
            return
        parsed = self._parse_humans_txt(result[1])
        if not parsed["team"] and not parsed["tech_credits"]:
            return
        tags = []
        if parsed["team"]:
            tags.append("intel:employee-pii")
        if parsed["tech_credits"]:
            tags.append("intel:tech-stack")
        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "source": "humans_txt",
                "intel_type": "employee_info",
                "tags": tags,
                "data": parsed,
            },
        )

    # ------------------------------------------------------------------ .well-known
    async def _probe_well_known(
        self, session, base_url, target_id, asset_id, rate_limiter
    ) -> None:
        async def _probe_one(path: str) -> None:
            result = await self._get(session, f"{base_url}/.well-known/{path}", rate_limiter)
            if not result or result[0] not in (200, 301, 302, 307, 308):
                return
            tags = ["intel:hidden-path"]
            if path in _WELL_KNOWN_AUTH:
                tags.append("candidate:authn-bypass")
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "well_known_probe",
                    "intel_type": "well_known_endpoint",
                    "tags": tags,
                    "data": {"path": f"/.well-known/{path}", "status_code": result[0]},
                },
            )

        await asyncio.gather(
            *[_probe_one(p) for p in _WELL_KNOWN_PATHS],
            return_exceptions=True,
        )

    # ------------------------------------------------------------------ pure parsers
    def _tags_for_path(self, path: str) -> list[str]:
        tags = ["intel:hidden-path"]
        if any(path.lower().startswith(p) for p in _SENSITIVE_PREFIXES):
            tags += ["candidate:forced-browsing", "candidate:authn-bypass"]
        return tags

    def _parse_robots(self, content: str) -> dict:
        def _lines(field: str) -> list[str]:
            return [
                m.strip()
                for m in re.findall(rf"^{field}:\s*(.+)", content, re.IGNORECASE | re.MULTILINE)
                if m.strip()
            ]
        return {
            "disallow": _lines("Disallow"),
            "allow": _lines("Allow"),
            "user_agents": [u for u in _lines("User-agent") if u != "*"],
            "sitemaps": _lines("Sitemap"),
        }

    def _parse_sitemap(self, content: str) -> dict:
        nested = re.findall(
            r"<sitemap[^>]*>.*?<loc>(.*?)</loc>.*?</sitemap>",
            content, re.IGNORECASE | re.DOTALL,
        )
        clean = re.sub(r"<sitemap[^>]*>.*?</sitemap>", "", content, flags=re.IGNORECASE | re.DOTALL)
        urls = re.findall(r"<loc>(.*?)</loc>", clean, re.IGNORECASE | re.DOTALL)
        return {
            "urls": [u.strip() for u in urls if u.strip()],
            "nested_sitemaps": [u.strip() for u in nested if u.strip()][:_SITEMAP_CHILD_CAP],
        }

    def _parse_security_txt(self, content: str) -> dict:
        def _field(name: str) -> list[str]:
            return [
                m.strip()
                for m in re.findall(rf"^{name}:\s*(.+)", content, re.IGNORECASE | re.MULTILINE)
                if m.strip()
            ]
        return {
            "contacts": _field("Contact"),
            "policies": _field("Policy"),
            "encryption": _field("Encryption"),
            "acknowledgments": _field("Acknowledgments"),
            "hiring": _field("Hiring"),
            "expires": next(iter(_field("Expires")), None),
            "canonical": _field("Canonical"),
            "preferred_languages": _field("Preferred-Languages"),
        }

    def _parse_humans_txt(self, content: str) -> dict:
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in content.splitlines():
            stripped = line.strip()
            m = re.match(r"/\*\s*(.+?)\s*\*/", stripped)
            if m:
                current = m.group(1).upper()
                sections[current] = []
            elif current and stripped:
                sections[current].append(stripped)

        team = []
        for line in sections.get("TEAM", []):
            if ":" in line:
                key, _, val = line.partition(":")
                team.append({"field": key.strip(), "value": val.strip()})

        tech_credits = sections.get("SITE", []) + sections.get("TECHNOLOGY", [])
        return {
            "team": team,
            "tech_credits": tech_credits,
            "raw_sections": {
                k: v for k, v in sections.items() if k not in ("TEAM", "SITE", "TECHNOLOGY")
            },
        }
```

- [ ] **Step 2: Run all MetafileParser tests**

```
pytest tests/test_info_gathering_metafiles.py -v -k "TestParseRobots or TestTagsForPath or TestParseSitemap or TestParseSecurityTxt or TestParseHumansTxt or TestMetafileParserExecute"
```

Expected: All pass. If any fail, fix before continuing.

- [ ] **Step 3: Commit**

```bash
git add workers/info_gathering/tools/metafile_parser.py tests/test_info_gathering_metafiles.py
git commit -m "feat(info-gathering): rewrite MetafileParser for WSTG-INFO-03 coverage"
```

---

## Task 4: Write MetaTagAnalyzer tests

**Files:**
- Modify: `tests/test_info_gathering_metafiles.py`

These will fail until Task 5 creates the implementation.

- [ ] **Step 1: Append MetaTagAnalyzer tests to the test file**

```python
# Append to tests/test_info_gathering_metafiles.py

# ---------------------------------------------------------------------------
# MetaTagAnalyzer — pure parser tests
# ---------------------------------------------------------------------------

class TestMetaTagAnalyzerParsers:
    def setup_method(self):
        self.tool = MetaTagAnalyzer()

    def test_robots_meta_directive_extracted(self):
        html = '<html><head><meta name="robots" content="noindex, nofollow"></head><body></body></html>'
        result = self.tool._parse_meta_tags(html)
        assert result["robots_directive"] == "noindex, nofollow"

    def test_og_site_name_extracted(self):
        html = '<html><head><meta property="og:site_name" content="ExampleCorp"></head></html>'
        result = self.tool._parse_meta_tags(html)
        assert result["og_site_name"] == "ExampleCorp"

    def test_og_url_extracted(self):
        html = '<html><head><meta property="og:url" content="https://example.com/"></head></html>'
        result = self.tool._parse_meta_tags(html)
        assert result["og_url"] == "https://example.com/"

    def test_twitter_creator_extracted(self):
        html = '<html><head><meta name="twitter:creator" content="@alice"></head></html>'
        result = self.tool._parse_meta_tags(html)
        assert result["twitter_creator"] == "@alice"

    def test_twitter_site_extracted(self):
        html = '<html><head><meta name="twitter:site" content="@examplecorp"></head></html>'
        result = self.tool._parse_meta_tags(html)
        assert result["twitter_site"] == "@examplecorp"

    def test_generator_extracted(self):
        html = '<html><head><meta name="generator" content="WordPress 6.4.2"></head><body></body></html>'
        result = self.tool._parse_meta_tags(html)
        assert result["generator"] == "WordPress 6.4.2"

    def test_application_name_extracted(self):
        html = '<html><head><meta name="application-name" content="MyApp"></head></html>'
        result = self.tool._parse_meta_tags(html)
        assert result["application_name"] == "MyApp"

    def test_meta_outside_head_ignored(self):
        html = '<html><head></head><body><meta name="generator" content="WordPress 6.4.2"></body></html>'
        result = self.tool._parse_meta_tags(html)
        assert "generator" not in result

    def test_empty_head_returns_empty_dict(self):
        html = "<html><head><title>Test</title></head><body></body></html>"
        result = self.tool._parse_meta_tags(html)
        assert result == {}

    def test_meta_with_empty_content_not_included(self):
        html = '<html><head><meta name="generator" content=""></head></html>'
        result = self.tool._parse_meta_tags(html)
        assert "generator" not in result


# ---------------------------------------------------------------------------
# MetaTagAnalyzer — execute() behavior tests
# ---------------------------------------------------------------------------

class TestMetaTagAnalyzerExecute:
    def _make_mock_session(self, status: int, body: str):
        """Build a mock aiohttp.ClientSession that returns status/body for any GET."""
        mock_resp = AsyncMock()
        mock_resp.status = status
        mock_resp.text = AsyncMock(return_value=body)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        return mock_session

    @pytest.mark.anyio
    async def test_generator_tag_emits_meta_generator_observation(self):
        tool = MetaTagAnalyzer()
        target = MagicMock()
        target.base_domain = "example.com"
        html = '<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>'
        mock_session = self._make_mock_session(200, html)

        with patch("workers.info_gathering.tools.meta_tag_analyzer.aiohttp.ClientSession",
                   return_value=mock_session), \
             patch.object(tool, "acquire_rate_limit", new_callable=AsyncMock), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        gen_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("intel_type") == "meta_generator"
        ]
        assert len(gen_obs) == 1
        assert "intel:tech-stack" in gen_obs[0]["tags"]
        assert "candidate:version-disclosure" in gen_obs[0]["tags"]
        assert gen_obs[0]["data"]["generator"] == "WordPress 6.4.2"

    @pytest.mark.anyio
    async def test_robots_meta_emits_crawler_hint_observation(self):
        tool = MetaTagAnalyzer()
        target = MagicMock()
        target.base_domain = "example.com"
        html = '<html><head><meta name="robots" content="noindex"></head></html>'
        mock_session = self._make_mock_session(200, html)

        with patch("workers.info_gathering.tools.meta_tag_analyzer.aiohttp.ClientSession",
                   return_value=mock_session), \
             patch.object(tool, "acquire_rate_limit", new_callable=AsyncMock), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        robots_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("intel_type") == "meta_robots"
        ]
        assert len(robots_obs) == 1
        assert "intel:crawler-hint" in robots_obs[0]["tags"]
        assert robots_obs[0]["data"]["directive"] == "noindex"

    @pytest.mark.anyio
    async def test_og_tags_emit_social_observation(self):
        tool = MetaTagAnalyzer()
        target = MagicMock()
        target.base_domain = "example.com"
        html = (
            '<html><head>'
            '<meta property="og:site_name" content="ExampleCorp">'
            '<meta property="og:url" content="https://example.com/">'
            '</head></html>'
        )
        mock_session = self._make_mock_session(200, html)

        with patch("workers.info_gathering.tools.meta_tag_analyzer.aiohttp.ClientSession",
                   return_value=mock_session), \
             patch.object(tool, "acquire_rate_limit", new_callable=AsyncMock), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        social_obs = [
            c.kwargs["tech_stack"] for c in mock_save.call_args_list
            if c.kwargs.get("tech_stack", {}).get("intel_type") == "meta_social"
        ]
        assert len(social_obs) == 1
        assert "intel:social-account" in social_obs[0]["tags"]
        assert "intel:site-structure" in social_obs[0]["tags"]
        assert social_obs[0]["data"]["og_site_name"] == "ExampleCorp"

    @pytest.mark.anyio
    async def test_no_relevant_tags_writes_no_observations(self):
        tool = MetaTagAnalyzer()
        target = MagicMock()
        target.base_domain = "example.com"
        html = "<html><head><title>Plain</title></head><body></body></html>"
        mock_session = self._make_mock_session(200, html)

        with patch("workers.info_gathering.tools.meta_tag_analyzer.aiohttp.ClientSession",
                   return_value=mock_session), \
             patch.object(tool, "acquire_rate_limit", new_callable=AsyncMock), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        assert mock_save.call_count == 0

    @pytest.mark.anyio
    async def test_non_200_response_writes_no_observations(self):
        tool = MetaTagAnalyzer()
        target = MagicMock()
        target.base_domain = "example.com"
        mock_session = self._make_mock_session(404, "")

        with patch("workers.info_gathering.tools.meta_tag_analyzer.aiohttp.ClientSession",
                   return_value=mock_session), \
             patch.object(tool, "acquire_rate_limit", new_callable=AsyncMock), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as mock_save:
            await tool.execute(target_id=1, asset_id=99, target=target)

        assert mock_save.call_count == 0

    @pytest.mark.anyio
    async def test_missing_asset_id_returns_early(self):
        tool = MetaTagAnalyzer()
        target = MagicMock()
        target.base_domain = "example.com"

        with patch("workers.info_gathering.tools.meta_tag_analyzer.aiohttp.ClientSession") as mock_cls, \
             patch.object(tool, "acquire_rate_limit", new_callable=AsyncMock):
            await tool.execute(target_id=1, asset_id=None, target=target)

        mock_cls.assert_not_called()
```

- [ ] **Step 2: Run these tests — confirm they all fail**

```
pytest tests/test_info_gathering_metafiles.py -v -k "TestMetaTagAnalyzer"
```

Expected: `ImportError` — `meta_tag_analyzer.py` doesn't exist yet.

---

## Task 5: Implement MetaTagAnalyzer

**Files:**
- Create: `workers/info_gathering/tools/meta_tag_analyzer.py`

- [ ] **Step 1: Create the file**

```python
# workers/info_gathering/tools/meta_tag_analyzer.py
"""MetaTagAnalyzer — WSTG-INFO-03: extract <meta> tags from page root for information leakage."""

from html.parser import HTMLParser

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool


class _HeadMetaCollector(HTMLParser):
    """Collects <meta> tag attribute dicts from the HTML <head> only."""

    def __init__(self):
        super().__init__()
        self.metas: list[dict[str, str]] = []
        self._in_head = False
        self._done = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._done:
            return
        if tag == "head":
            self._in_head = True
        elif tag == "body":
            self._done = True
        elif tag == "meta" and self._in_head:
            self.metas.append({k: (v or "") for k, v in attrs})

    def handle_endtag(self, tag: str) -> None:
        if tag in ("head",):
            self._done = True


class MetaTagAnalyzer(InfoGatheringTool):
    """Extract <meta> tags from the page root and tag findings for downstream workers."""

    async def execute(self, target_id: int, **kwargs) -> None:
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or asset_id is None:
            return

        host = kwargs.get("host") or target.base_domain
        rate_limiter = kwargs.get("rate_limiter")
        await self.acquire_rate_limit(rate_limiter)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{host}/",
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return
                    html = await resp.text(errors="replace")
        except Exception:
            return

        findings = self._parse_meta_tags(html)

        if findings.get("robots_directive"):
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "meta_tag",
                    "intel_type": "meta_robots",
                    "tags": ["intel:crawler-hint"],
                    "data": {"directive": findings["robots_directive"]},
                },
            )

        social = {
            k: v for k, v in findings.items()
            if k.startswith(("og_", "twitter_")) and v
        }
        if social:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "meta_tag",
                    "intel_type": "meta_social",
                    "tags": ["intel:social-account", "intel:site-structure"],
                    "data": social,
                },
            )

        generator = {k: v for k, v in findings.items() if k in ("generator", "application_name") and v}
        if generator:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "source": "meta_tag",
                    "intel_type": "meta_generator",
                    "tags": ["intel:tech-stack", "candidate:version-disclosure"],
                    "data": generator,
                },
            )

    def _parse_meta_tags(self, html: str) -> dict[str, str]:
        collector = _HeadMetaCollector()
        collector.feed(html)

        result: dict[str, str] = {}
        for meta in collector.metas:
            name = (meta.get("name") or meta.get("property") or "").lower()
            content = meta.get("content", "")
            if not content:
                continue

            if name == "robots":
                result["robots_directive"] = content
            elif name == "og:url":
                result["og_url"] = content
            elif name == "og:site_name":
                result["og_site_name"] = content
            elif name == "og:title":
                result["og_title"] = content
            elif name == "twitter:creator":
                result["twitter_creator"] = content
            elif name == "twitter:site":
                result["twitter_site"] = content
            elif name == "twitter:card":
                result["twitter_card"] = content
            elif name == "generator":
                result["generator"] = content
            elif name == "application-name":
                result["application_name"] = content

        return result
```

- [ ] **Step 2: Run all MetaTagAnalyzer tests**

```
pytest tests/test_info_gathering_metafiles.py -v -k "TestMetaTagAnalyzer"
```

Expected: All pass.

- [ ] **Step 3: Commit**

```bash
git add workers/info_gathering/tools/meta_tag_analyzer.py tests/test_info_gathering_metafiles.py
git commit -m "feat(info-gathering): add MetaTagAnalyzer for WSTG-INFO-03 meta tag extraction"
```

---

## Task 6: Wire Stage 3 in pipeline.py

**Files:**
- Modify: `workers/info_gathering/pipeline.py:44-75`

- [ ] **Step 1: Add the import**

In `workers/info_gathering/pipeline.py`, find this block:

```python
from .tools.metafile_parser import MetafileParser
from .tools.method_probe import MethodProbe
```

Replace with:

```python
from .tools.meta_tag_analyzer import MetaTagAnalyzer
from .tools.metafile_parser import MetafileParser
from .tools.method_probe import MethodProbe
```

- [ ] **Step 2: Update Stage 3 tools list**

Find:

```python
    Stage(name="web_server_metafiles", section_id="4.1.3", tools=[MetafileParser]),
```

Replace with:

```python
    Stage(name="web_server_metafiles", section_id="4.1.3", tools=[MetafileParser, MetaTagAnalyzer]),
```

- [ ] **Step 3: Run the full test suite**

```
pytest tests/test_info_gathering_metafiles.py tests/test_info_gathering_base_tool.py tests/test_info_gathering_stage2_integration.py -v
```

Expected: All pass. Any failures in the Stage 2 integration tests indicate a pipeline import regression — check for syntax errors in the modified files.

- [ ] **Step 4: Commit**

```bash
git add workers/info_gathering/pipeline.py
git commit -m "feat(info-gathering): wire MetafileParser + MetaTagAnalyzer into Stage 3"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|-----------------|------|
| robots.txt — Disallow, Allow, User-Agent, Sitemap refs | Task 3 |
| robots.txt Sitemap: refs fed into sitemap fetcher | Task 3 (`_fetch_robots` returns refs → `_fetch_sitemap` extra_urls) |
| sitemap.xml — recursive index expansion (1 level, max 3 children) | Task 3 |
| sitemap.xml — 500 URL cap, 50-per-batch observations | Task 3 |
| security.txt — both paths probed, prefers .well-known/ | Task 3 |
| security.txt — all RFC 9116 fields parsed | Task 3 |
| humans.txt — TEAM, SITE, TECHNOLOGY sections | Task 3 |
| .well-known/ curated 13-path probe | Task 3 |
| .well-known/ auth paths get candidate:authn-bypass | Task 3 |
| HTML `<meta>` robots directive | Task 5 |
| HTML `<meta>` OG / Twitter Card tags | Task 5 |
| HTML `<meta>` generator / application-name | Task 5 |
| Tag taxonomy applied to all observations | Tasks 3, 5 |
| Bug fix: save_observation uses asset_id keyword | Task 3 |
| pipeline.py Stage 3 wired with both tools | Task 6 |

All spec requirements have a corresponding task.
