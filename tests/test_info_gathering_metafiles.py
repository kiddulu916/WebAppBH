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
