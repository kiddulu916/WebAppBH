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

    def test_prefix_match_is_not_word_boundary(self):
        # /admin is a prefix of /administrator — startswith match is intentional
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
            await tool.execute(target_id=1, asset_id=99, target=target)

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
        """Stops after the first 200 (prefers /.well-known/), writes exactly one observation."""
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
