# workers/info_gathering/tools/js_secret_scanner.py
"""JsSecretScanner — find hardcoded secrets in JS files via trufflehog and gitleaks (WSTG-INFO-05)."""
import json
import os
import re
import tempfile
from pathlib import Path

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, Observation, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger


class JsSecretScanner(InfoGatheringTool):
    """Download JS assets and scan them with trufflehog and gitleaks for hardcoded secrets."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        candidates = await self._get_js_assets(target_id)
        if not candidates:
            candidates = await self._js_from_root(target.base_domain, target_id)
        if not candidates:
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            downloaded, path_to_asset = await self._download_js(candidates, tmpdir)
            if not downloaded:
                return

            th_output = ""
            gl_report = os.path.join(tmpdir, "gl_report.json")

            try:
                th_output = await self.run_subprocess(
                    ["trufflehog", "filesystem", tmpdir, "--json", "--no-update"],
                    timeout=120,
                )
            except Exception as exc:
                logger.debug("trufflehog failed", error=str(exc))

            try:
                await self.run_subprocess(
                    [
                        "gitleaks", "detect",
                        "--source", tmpdir,
                        "--no-git",
                        "--report-format", "json",
                        "--report-path", gl_report,
                        "--exit-code", "0",
                    ],
                    timeout=120,
                )
            except Exception as exc:
                logger.debug("gitleaks failed", error=str(exc))

            findings = self._deduplicate(
                self._parse_trufflehog(th_output) + self._parse_gitleaks(gl_report, tmpdir=tmpdir)
            )

            for _, asset_id in candidates:
                await self.save_observation(
                    asset_id=asset_id,
                    tech_stack={"_source": "js_secret_scanner", "secrets_found": len(findings)},
                )

            for finding in findings:
                detector = finding['detector']
                short_detector = detector if len(detector) <= 450 else detector[:447] + "..."
                finding_asset_id = path_to_asset.get(finding.get("file", ""))
                await self.save_vulnerability(
                    target_id=target_id,
                    asset_id=finding_asset_id,
                    severity="medium",
                    title=f"Hardcoded secret in JavaScript: {short_detector}",
                    description=(
                        f"{finding['tool']} detected a {finding['detector']} secret "
                        f"in {finding['file']}. Verified: {finding['verified']}."
                    ),
                    source_tool="js_secret_scanner",
                    section_id="4.1.5",
                    vuln_type="hardcoded_secret",
                    evidence=finding,
                )

    async def _get_js_assets(self, target_id: int) -> list[tuple[str, int]]:
        """Return (url, asset_id) for .js assets not yet processed by this tool."""
        async with get_session() as session:
            stmt = (
                select(Asset.asset_value, Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                    Asset.asset_value.like("%.js"),
                )
            )
            result = await session.execute(stmt)
            all_assets = result.all()
            if not all_assets:
                return []

            asset_ids = [row[1] for row in all_assets]
            processed_stmt = (
                select(Observation.asset_id)
                .where(
                    Observation.asset_id.in_(asset_ids),
                    Observation.tech_stack["_source"].astext == "js_secret_scanner",
                )
            )
            processed_result = await session.execute(processed_stmt)
            processed_ids = {row[0] for row in processed_result.all()}

            return [(url, aid) for url, aid in all_assets if aid not in processed_ids]

    async def _js_from_root(self, base_domain: str, target_id: int) -> list[tuple[str, int]]:
        """Parse root page <script src> links; create Asset records."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://{base_domain}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
        except Exception as exc:
            logger.debug("js_secret_scanner fallback fetch failed", error=str(exc))
            return []

        hrefs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
        results = []
        for href in hrefs:
            if href.startswith("//"):
                full_url = "https:" + href
            elif href.startswith("http"):
                full_url = href
            else:
                full_url = f"https://{base_domain}{href if href.startswith('/') else '/' + href}"
            aid = await self.save_asset(target_id, "url", full_url, "js_secret_scanner")
            if aid is None:
                async with get_session() as session:
                    stmt = select(Asset.id).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == full_url,
                    )
                    r = await session.execute(stmt)
                    aid = r.scalar_one_or_none()
            if aid:
                results.append((full_url, aid))
        return results

    async def _download_js(
        self, candidates: list[tuple[str, int]], tmpdir: str
    ) -> tuple[list[str], dict[str, int]]:
        """Download JS files into tmpdir; return (file_paths, path_to_asset_id mapping)."""
        downloaded = []
        path_to_asset: dict[str, int] = {}
        async with aiohttp.ClientSession() as http:
            for i, (url, asset_id) in enumerate(candidates):
                try:
                    async with http.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            content = await resp.text(errors="replace")
                            path = os.path.join(tmpdir, f"js_{i}.js")
                            Path(path).write_text(content, encoding="utf-8")
                            downloaded.append(path)
                            path_to_asset[path] = asset_id
                except Exception:
                    continue
        return downloaded, path_to_asset

    def _parse_trufflehog(self, output: str) -> list[dict]:
        """Parse trufflehog --json NDJSON output into normalised finding dicts."""
        findings = []
        for line in output.strip().splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "tool": "trufflehog",
                    "detector": obj.get("DetectorName", "unknown"),
                    "secret": obj.get("Raw", ""),
                    "verified": obj.get("Verified", False),
                    "file": (
                        (obj.get("SourceMetadata") or {})
                        .get("Data", {})
                        .get("Filesystem", {})
                        .get("file", "")
                    ),
                })
            except json.JSONDecodeError:
                continue
        return findings

    def _parse_gitleaks(self, report_path: str, tmpdir: str = "") -> list[dict]:
        """Parse gitleaks JSON report file into normalised finding dicts."""
        try:
            with open(report_path) as f:
                data = json.load(f)
            return [
                {
                    "tool": "gitleaks",
                    "detector": item.get("RuleID", "unknown"),
                    "secret": item.get("Secret", ""),
                    "verified": False,
                    "file": (
                        os.path.join(tmpdir, item.get("File", ""))
                        if tmpdir and item.get("File", "")
                        else item.get("File", "")
                    ),
                }
                for item in (data or [])
            ]
        except (json.JSONDecodeError, FileNotFoundError, OSError):
            return []

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Return findings with duplicates removed; key is (tool, detector, file, secret)."""
        seen: set[tuple] = set()
        unique = []
        for f in findings:
            key = (f.get("tool", ""), f.get("detector", ""), f.get("file", ""), f.get("secret", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
