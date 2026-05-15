# workers/info_gathering/tools/metadata_extractor.py
"""MetadataExtractor wrapper — extract metadata from documents and files."""

import asyncio
import aiohttp
import json
import tempfile
import os

from workers.info_gathering.base_tool import InfoGatheringTool


class MetadataExtractor(InfoGatheringTool):
    """Extract metadata from PDF, DOC, and other files."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        from lib_webbh.database import Asset
        from lib_webbh import get_session
        from sqlalchemy import select

        # Get URLs that might contain documents
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "url",
            )
            result = await session.execute(stmt)
            urls = [row[0] for row in result.all()]

        doc_urls = [u for u in urls if any(u.lower().endswith(ext) for ext in
                    ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'])]

        for url in doc_urls[:10]:  # Limit to 10 docs
            try:
                metadata = await self._extract_metadata(url)
                if metadata:
                    await self.save_observation(
                        target_id, "metadata",
                        {"url": url, "metadata": metadata},
                        "metadata_extractor"
                    )
            except Exception:
                continue

    async def _extract_metadata(self, url: str) -> dict:
        """Download and extract metadata from a file."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        with tempfile.NamedTemporaryFile(delete=False) as f:
                            f.write(content)
                            tmp_path = f.name

                        try:
                            proc = await asyncio.create_subprocess_exec(
                                "exiftool", "-json", tmp_path,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            stdout_bytes, _ = await asyncio.wait_for(
                                proc.communicate(), timeout=30
                            )
                            if proc.returncode == 0:
                                data = json.loads(stdout_bytes.decode("utf-8", errors="replace"))
                                return data[0] if data else {}
                        except asyncio.TimeoutError:
                            pass
                        finally:
                            if os.path.exists(tmp_path):
                                os.unlink(tmp_path)
        except Exception:
            pass
        return {}