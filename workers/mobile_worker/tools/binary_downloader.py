"""BinaryDownloaderTool -- Stage 1: acquire APK/IPA binaries.

Three acquisition channels:
1. Download from URLs in assets table (.apk/.ipa)
2. apkeep for Play Store links (best-effort)
3. Manual drop folder scan
"""

from __future__ import annotations

import os
from pathlib import Path

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.mobile_worker.base_tool import MobileTestTool, MOBILE_ANALYSIS_DIR
from workers.mobile_worker.concurrency import WeightClass

logger = setup_logger("binary-downloader")


class BinaryDownloaderTool(MobileTestTool):
    """Acquire mobile binaries from URLs, Play Store, and drop folder."""

    name = "binary_downloader"
    weight_class = WeightClass.STATIC

    MAX_BINARY_SIZE = 104_857_600  # 100MB

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping binary_downloader -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0}

        output_dir = Path(MOBILE_ANALYSIS_DIR) / str(target_id)
        output_dir.mkdir(parents=True, exist_ok=True)

        stats: dict = {"found": 0, "in_scope": 0, "new": 0}

        # Channel 1: download from asset URLs
        urls = await self._get_binary_urls(target_id)
        for asset_id, url in urls:
            try:
                downloaded = await self._download_binary(url, output_dir, log)
                if downloaded:
                    stats["found"] += 1
                    stats["new"] += 1
            except Exception as exc:
                log.error(f"Download failed for {url}: {exc}")

        # Channel 2: apkeep for Play Store links (best-effort)
        for asset_id, url in urls:
            if "play.google.com" in url:
                try:
                    pkg = self._extract_play_package(url)
                    if pkg:
                        await self._apkeep_download(pkg, output_dir, log)
                        stats["found"] += 1
                except Exception as exc:
                    log.warning(f"apkeep failed for {url}: {exc}")

        # Channel 3: manual drop folder
        drop_files = self._scan_drop_folder(target_id)
        for fpath in drop_files:
            dest = output_dir / Path(fpath).name
            if not dest.exists():
                import shutil
                shutil.copy2(fpath, dest)
                stats["found"] += 1
                stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("binary_downloader complete", extra=stats)
        return stats

    async def _download_binary(self, url: str, output_dir: Path, log) -> bool:
        """Download a binary with size limit enforcement."""
        import httpx

        filename = Path(url.split("?")[0].split("/")[-1]).name
        dest = output_dir / filename
        if dest.exists():
            log.info(f"Already downloaded: {filename}")
            return False

        async with httpx.AsyncClient(follow_redirects=True, timeout=120) as client:
            # Check Content-Length first
            head_resp = await client.head(url)
            content_length = int(head_resp.headers.get("content-length", "0"))
            if content_length > self.MAX_BINARY_SIZE:
                log.warning(f"Skipping {url}: size {content_length} exceeds limit")
                return False

            # Stream download
            async with client.stream("GET", url) as resp:
                resp.raise_for_status()
                downloaded = 0
                with open(dest, "wb") as f:
                    async for chunk in resp.aiter_bytes(8192):
                        downloaded += len(chunk)
                        if downloaded > self.MAX_BINARY_SIZE:
                            log.warning(f"Aborting {url}: exceeded size limit during download")
                            f.close()
                            dest.unlink(missing_ok=True)
                            return False
                        f.write(chunk)

        log.info(f"Downloaded {filename} ({downloaded} bytes)")
        return True

    @staticmethod
    def _extract_play_package(url: str) -> str | None:
        """Extract package ID from a Play Store URL."""
        if "id=" in url:
            return url.split("id=")[1].split("&")[0]
        return None

    async def _apkeep_download(self, package: str, output_dir: Path, log) -> None:
        """Best-effort download via apkeep."""
        cmd = ["apkeep", "-a", package, str(output_dir)]
        try:
            await self.run_subprocess(cmd, timeout=120)
            log.info(f"apkeep downloaded {package}")
        except Exception as exc:
            log.warning(f"apkeep failed for {package}: {exc}")
