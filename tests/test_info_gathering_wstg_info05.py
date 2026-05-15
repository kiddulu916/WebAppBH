# tests/test_info_gathering_wstg_info05.py
"""Tests for WSTG-INFO-05 Stage 5 tools."""
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.tools.metadata_extractor import MetadataExtractor


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


from workers.info_gathering.tools.source_map_prober import SourceMapProber


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
