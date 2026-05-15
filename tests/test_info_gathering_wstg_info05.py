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
    async def test_exiftool_called_via_create_subprocess_exec(self, tmp_path):
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
    async def test_returns_empty_dict_on_nonzero_returncode(self, tmp_path):
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
