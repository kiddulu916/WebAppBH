# tests/test_info_gathering_wstg_info05.py
"""Tests for WSTG-INFO-05 Stage 5 tools."""
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.tools.js_secret_scanner import JsSecretScanner
from workers.info_gathering.tools.metadata_extractor import MetadataExtractor
from workers.info_gathering.tools.redirect_body_inspector import RedirectBodyInspector
from workers.info_gathering.tools.source_map_prober import SourceMapProber


class TestMetadataExtractorAsyncSubprocess:
    @pytest.mark.anyio
    async def test_exiftool_called_via_create_subprocess_exec(self):
        """_extract_metadata must use asyncio.create_subprocess_exec, not subprocess.run."""
        tool = MetadataExtractor()
        fake_url = "https://example.com/report.pdf"

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b'[{"Author": "Alice", "Creator": "Word"}]', b"")
        )
        mock_proc.returncode = 0

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=b"%PDF fake content")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec, \
             patch("workers.info_gathering.tools.metadata_extractor.aiohttp.ClientSession",
                   return_value=mock_session), \
             patch("tempfile.NamedTemporaryFile") as mock_tmp, \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"):

            fake_file = MagicMock()
            fake_file.name = "/tmp/test_doc.pdf"
            mock_tmp.return_value.__enter__.return_value = fake_file

            result = await tool._extract_metadata(fake_url)

        mock_exec.assert_called_once()
        args = mock_exec.call_args[0]
        assert args[0] == "exiftool"
        assert args[1] == "-json"
        assert result == {"Author": "Alice", "Creator": "Word"}

    @pytest.mark.anyio
    async def test_returns_empty_dict_on_nonzero_returncode(self):
        """_extract_metadata returns {} when exiftool exits non-zero."""
        tool = MetadataExtractor()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
        mock_proc.returncode = 1

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=b"content")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("workers.info_gathering.tools.metadata_extractor.aiohttp.ClientSession",
                   return_value=mock_session), \
             patch("tempfile.NamedTemporaryFile") as mock_tmp, \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"):

            fake_file = MagicMock()
            fake_file.name = "/tmp/test_doc.pdf"
            mock_tmp.return_value.__enter__.return_value = fake_file

            result = await tool._extract_metadata("https://example.com/doc.pdf")

        assert result == {}

    @pytest.mark.anyio
    async def test_returns_empty_dict_on_timeout(self):
        """_extract_metadata returns {} when exiftool times out."""
        tool = MetadataExtractor()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=b"content")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()), \
             patch("workers.info_gathering.tools.metadata_extractor.aiohttp.ClientSession") as mock_http, \
             patch("tempfile.NamedTemporaryFile") as mock_tmp, \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"):

            mock_session = AsyncMock()
            mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)

            fake_file = MagicMock()
            fake_file.name = "/tmp/test_doc.pdf"
            mock_tmp.return_value.__enter__ = MagicMock(return_value=fake_file)
            mock_tmp.return_value.__exit__ = MagicMock(return_value=False)

            result = await tool._extract_metadata("https://example.com/doc.pdf")

        assert result == {}


class TestSourceMapProber:
    @pytest.mark.anyio
    async def test_saves_vuln_when_map_exposed(self):
        """SourceMapProber saves a Vulnerability when the .map URL returns 200."""
        tool = SourceMapProber()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_candidates", new_callable=AsyncMock,
                          return_value=[("https://example.com/app.js", 1)]),              patch.object(tool, "_probe_map", new_callable=AsyncMock, return_value=True),              patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=10) as save_obs,              patch.object(tool, "save_vulnerability", new_callable=AsyncMock, return_value=5) as save_vuln:

            await tool.execute(target_id=1, target=target)

        save_obs.assert_awaited_once()
        obs_kwargs = save_obs.call_args.kwargs
        assert obs_kwargs["asset_id"] == 1
        assert obs_kwargs["tech_stack"]["_source"] == "source_map_prober"
        assert obs_kwargs["tech_stack"]["map_url"] == "https://example.com/app.js.map"

        save_vuln.assert_awaited_once()
        vuln_kwargs = save_vuln.call_args.kwargs
        assert vuln_kwargs["severity"] == "medium"
        assert vuln_kwargs["vuln_type"] == "source_map_exposure"
        assert vuln_kwargs["evidence"]["map_url"] == "https://example.com/app.js.map"

    @pytest.mark.anyio
    async def test_no_vuln_when_map_not_exposed(self):
        """SourceMapProber does not save a Vulnerability when .map returns non-200."""
        tool = SourceMapProber()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_candidates", new_callable=AsyncMock,
                          return_value=[("https://example.com/app.js", 1)]),              patch.object(tool, "_probe_map", new_callable=AsyncMock, return_value=False),              patch.object(tool, "save_observation", new_callable=AsyncMock) as save_obs,              patch.object(tool, "save_vulnerability", new_callable=AsyncMock) as save_vuln:

            await tool.execute(target_id=1, target=target)

        save_obs.assert_not_awaited()
        save_vuln.assert_not_awaited()

    @pytest.mark.anyio
    async def test_falls_back_to_root_when_db_empty(self):
        """SourceMapProber calls _candidates_from_root when _get_candidates returns []."""
        tool = SourceMapProber()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_candidates", new_callable=AsyncMock, return_value=[]),              patch.object(tool, "_candidates_from_root", new_callable=AsyncMock,
                          return_value=[("https://example.com/main.js", 2)]) as from_root,              patch.object(tool, "_probe_map", new_callable=AsyncMock, return_value=False),              patch.object(tool, "save_observation", new_callable=AsyncMock),              patch.object(tool, "save_vulnerability", new_callable=AsyncMock):

            await tool.execute(target_id=1, target=target)

        from_root.assert_awaited_once_with("example.com", 1)

    @pytest.mark.anyio
    async def test_probe_map_returns_true_on_200(self):
        """_probe_map returns True when HEAD to .map URL yields 200."""
        tool = SourceMapProber()
        map_url = "https://example.com/app.js.map"

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_http = MagicMock()
        mock_http.head.return_value = mock_resp
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)

        with patch("workers.info_gathering.tools.source_map_prober.aiohttp.ClientSession", return_value=mock_http):
            result = await tool._probe_map(map_url)

        assert result is True

    @pytest.mark.anyio
    async def test_probe_map_returns_false_on_404(self):
        """_probe_map returns False when HEAD to .map URL yields 404."""
        tool = SourceMapProber()

        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_http = MagicMock()
        mock_http.head.return_value = mock_resp
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)

        with patch("workers.info_gathering.tools.source_map_prober.aiohttp.ClientSession", return_value=mock_http):
            result = await tool._probe_map("https://example.com/app.js.map")

        assert result is False

    @pytest.mark.anyio
    async def test_probe_map_falls_back_to_get_on_405(self):
        """HEAD 405 triggers GET fallback; returns True when GET is 200."""
        prober = SourceMapProber()
        head_resp = MagicMock()
        head_resp.status = 405
        head_resp.__aenter__ = AsyncMock(return_value=head_resp)
        head_resp.__aexit__ = AsyncMock(return_value=False)

        get_resp = MagicMock()
        get_resp.status = 200
        get_resp.__aenter__ = AsyncMock(return_value=get_resp)
        get_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.head = MagicMock(return_value=head_resp)
        mock_session.get = MagicMock(return_value=get_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "workers.info_gathering.tools.source_map_prober.aiohttp.ClientSession",
            return_value=mock_session,
        ):
            result = await prober._probe_map("https://example.com/app.js.map")

        assert result is True
        mock_session.head.assert_called_once()
        mock_session.get.assert_called_once()


class TestRedirectBodyInspector:
    @pytest.mark.anyio
    async def test_calls_inspect_for_each_candidate(self):
        """execute() calls _inspect once per URL candidate."""
        tool = RedirectBodyInspector()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_url_assets", new_callable=AsyncMock,
                          return_value=[("https://example.com/login", 1)]), \
             patch.object(tool, "_inspect", new_callable=AsyncMock) as mock_inspect:

            await tool.execute(target_id=1, target=target)

        mock_inspect.assert_awaited_once_with("https://example.com/login", 1, 1)

    def test_scan_body_detects_credential_keyword(self):
        """_scan_body returns matches for credential-like strings."""
        tool = RedirectBodyInspector()
        body = 'Redirecting... api_key=supersecret123'
        matches = tool._scan_body(body)
        types = [t for _, t in matches]
        assert "credential_keyword" in types

    def test_scan_body_detects_internal_ip(self):
        """_scan_body returns matches for RFC-1918 IP addresses."""
        tool = RedirectBodyInspector()
        body = "Server at 10.0.1.42 is unavailable"
        matches = tool._scan_body(body)
        types = [t for _, t in matches]
        assert "internal_ip" in types

    def test_scan_body_detects_stack_trace(self):
        """_scan_body returns matches for Python/Java stack trace patterns."""
        tool = RedirectBodyInspector()
        body = "Traceback (most recent call last):\n  File 'app.py', line 42"
        matches = tool._scan_body(body)
        types = [t for _, t in matches]
        assert "stack_trace" in types

    def test_scan_body_returns_empty_for_clean_body(self):
        """_scan_body returns [] for body with no sensitive patterns."""
        tool = RedirectBodyInspector()
        body = "302 Found. Please follow the redirect."
        matches = tool._scan_body(body)
        assert matches == []

    @pytest.mark.anyio
    async def test_inspect_saves_observation_and_vuln_on_match(self):
        """_inspect saves Observation unconditionally; Vulnerability only when patterns match."""
        tool = RedirectBodyInspector()

        mock_resp = MagicMock()
        mock_resp.status = 302
        mock_resp.text = AsyncMock(return_value="password=hunter2")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch.object(tool, "save_observation", new_callable=AsyncMock) as save_obs, \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock) as save_vuln, \
             patch(
                 "workers.info_gathering.tools.redirect_body_inspector.aiohttp.ClientSession",
                 return_value=mock_session,
             ):
            await tool._inspect("https://example.com/login", asset_id=1, target_id=1)

        save_obs.assert_awaited_once()
        assert save_obs.call_args.kwargs["tech_stack"]["_source"] == "redirect_body_inspector"
        save_vuln.assert_awaited_once()
        assert save_vuln.call_args.kwargs["vuln_type"] == "redirect_body_leakage"

    @pytest.mark.anyio
    async def test_inspect_skips_non_3xx_response(self):
        """_inspect must not save Observation or Vulnerability for non-redirect responses."""
        tool = RedirectBodyInspector()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch.object(tool, "save_observation", new_callable=AsyncMock) as save_obs, \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock) as save_vuln, \
             patch(
                 "workers.info_gathering.tools.redirect_body_inspector.aiohttp.ClientSession",
                 return_value=mock_session,
             ):
            await tool._inspect("https://example.com/page", asset_id=1, target_id=1)

        save_obs.assert_not_awaited()
        save_vuln.assert_not_awaited()

    @pytest.mark.anyio
    async def test_falls_back_to_root_when_db_empty(self):
        """execute() calls _urls_from_root when _get_url_assets returns []."""
        tool = RedirectBodyInspector()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_url_assets", new_callable=AsyncMock, return_value=[]), \
             patch.object(tool, "_urls_from_root", new_callable=AsyncMock,
                          return_value=[("https://example.com/login", 2)]) as from_root, \
             patch.object(tool, "_inspect", new_callable=AsyncMock):

            await tool.execute(target_id=1, target=target)

        from_root.assert_awaited_once_with("example.com", 1)


class TestJsSecretScanner:
    def test_parse_trufflehog_extracts_findings(self):
        """_parse_trufflehog parses NDJSON output from trufflehog filesystem."""
        tool = JsSecretScanner()
        ndjson = (
            '{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":false,'
            '"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/app.js"}}}}\n'
            '{"DetectorName":"GitHub","Raw":"ghp_abc123","Verified":true,'
            '"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/lib.js"}}}}\n'
        )
        findings = tool._parse_trufflehog(ndjson)
        assert len(findings) == 2
        assert findings[0]["tool"] == "trufflehog"
        assert findings[0]["detector"] == "AWS"
        assert findings[0]["secret"] == "AKIAIOSFODNN7EXAMPLE"
        assert findings[0]["verified"] is False
        assert findings[1]["secret"] == "ghp_abc123"
        assert findings[1]["verified"] is True

    def test_parse_trufflehog_skips_invalid_lines(self):
        """_parse_trufflehog skips non-JSON lines gracefully."""
        tool = JsSecretScanner()
        output = 'not json\n{"DetectorName":"AWS","Raw":"key","Verified":false,"SourceMetadata":{}}\n'
        findings = tool._parse_trufflehog(output)
        assert len(findings) == 1

    def test_parse_gitleaks_extracts_findings(self, tmp_path):
        """_parse_gitleaks reads the JSON report file gitleaks writes."""
        tool = JsSecretScanner()
        report = tmp_path / "report.json"
        report.write_text(json.dumps([
            {"RuleID": "aws-access-key", "Secret": "AKIAIOSFODNN7EXAMPLE", "File": "/tmp/app.js"},
            {"RuleID": "github-pat", "Secret": "ghp_xyz", "File": "/tmp/lib.js"},
        ]))
        findings = tool._parse_gitleaks(str(report))
        assert len(findings) == 2
        assert findings[0]["tool"] == "gitleaks"
        assert findings[0]["detector"] == "aws-access-key"
        assert findings[0]["secret"] == "AKIAIOSFODNN7EXAMPLE"
        assert findings[0]["verified"] is False

    def test_parse_gitleaks_returns_empty_on_missing_file(self):
        """_parse_gitleaks returns [] when the report file does not exist."""
        tool = JsSecretScanner()
        findings = tool._parse_gitleaks("/nonexistent/path/report.json")
        assert findings == []

    def test_deduplicate_removes_same_secret(self):
        """_deduplicate keeps only the first occurrence of each secret value."""
        tool = JsSecretScanner()
        findings = [
            {"tool": "trufflehog", "secret": "AKIA123", "detector": "AWS", "verified": False, "file": "a.js"},
            {"tool": "gitleaks",   "secret": "AKIA123", "detector": "aws-access-key", "verified": False, "file": "a.js"},
            {"tool": "trufflehog", "secret": "ghp_xyz", "detector": "GitHub", "verified": True, "file": "b.js"},
        ]
        unique = tool._deduplicate(findings)
        assert len(unique) == 2
        assert unique[0]["secret"] == "AKIA123"
        assert unique[1]["secret"] == "ghp_xyz"

    @pytest.mark.anyio
    async def test_execute_saves_observation_and_vuln(self):
        """execute() saves one Observation per JS asset and one Vulnerability per unique finding."""
        tool = JsSecretScanner()
        target = MagicMock(base_domain="example.com")

        th_output = '{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/js_0.js"}}}}\n'

        with patch.object(tool, "_get_js_assets", new_callable=AsyncMock,
                          return_value=[("https://example.com/app.js", 1)]), \
             patch.object(tool, "_download_js", new_callable=AsyncMock,
                          return_value=["/tmp/js_0.js"]), \
             patch.object(tool, "run_subprocess", new_callable=AsyncMock,
                          side_effect=[th_output, ""]), \
             patch.object(tool, "_parse_gitleaks", return_value=[]), \
             patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=10) as save_obs, \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock, return_value=5) as save_vuln:

            with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                mock_tmpdir.return_value.__enter__ = MagicMock(return_value="/tmp/fakedir")
                mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)
                await tool.execute(target_id=1, target=target)

        save_obs.assert_awaited_once()
        obs_kwargs = save_obs.call_args.kwargs
        assert obs_kwargs["asset_id"] == 1
        assert obs_kwargs["tech_stack"]["_source"] == "js_secret_scanner"

        save_vuln.assert_awaited_once()
        vuln_kwargs = save_vuln.call_args.kwargs
        assert vuln_kwargs["vuln_type"] == "hardcoded_secret"
        assert vuln_kwargs["severity"] == "medium"
        assert "AKIAIOSFODNN7EXAMPLE" in vuln_kwargs["evidence"]["secret"]
