"""Path confusion tester — WSTG-CONF-13."""
from __future__ import annotations

import asyncio
from datetime import datetime
from difflib import SequenceMatcher

import httpx
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf13")

_SECTION_ID = "WSTG-CONF-13"
_HTTP_CONCURRENCY = 20
_SIMILARITY_THRESHOLD = 0.85
_BODY_READ_LIMIT = 50_000

_CONFUSED_SUFFIXES = [".js", ".css", ".png", ".ico", ".json", ".woff"]
_NO_CACHE_DIRECTIVES = {"no-store", "private", "no-cache"}


def _is_cacheable(headers: dict) -> bool:
    """Return True if Cache-Control lacks all caching-prevention directives."""
    cache_control = headers.get("cache-control", "").lower()
    return not any(d in cache_control for d in _NO_CACHE_DIRECTIVES)


def _analyze_confused_response(
    seed_url: str,
    confused_url: str,
    baseline_body: str,
    confused_body: str,
    confused_headers: dict,
) -> dict | None:
    """Return a vulnerability dict if the confused path serves the original content, else None."""
    ratio = SequenceMatcher(None, baseline_body, confused_body).ratio()
    if ratio <= _SIMILARITY_THRESHOLD:
        return None

    cacheable = _is_cacheable(confused_headers)
    cache_control_value = confused_headers.get("cache-control", "(none)")
    severity = "high" if cacheable else "medium"

    return {
        "vulnerability": {
            "name": f"Path Confusion: {confused_url}",
            "severity": severity,
            "description": (
                f"{confused_url} returned content matching {seed_url} "
                f"(similarity {ratio:.0%}). Cache-Control: {cache_control_value}. "
                "A CDN may cache this response under the static-looking URL, "
                "exposing it to unauthenticated users."
            ),
            "location": confused_url,
            "section_id": _SECTION_ID,
        }
    }


class PathConfusionTester(ConfigMgmtTool):
    """Test for path confusion / web cache deception per WSTG-CONF-13."""

    name = "path_confusion_tester"

    def build_command(self, target, headers=None):
        raise NotImplementedError("PathConfusionTester uses native async execute()")

    def parse_output(self, stdout):
        raise NotImplementedError("PathConfusionTester uses native async execute()")

    async def _fetch_seed_urls(self, target_id: int) -> list[str]:
        """Pull confirmed url/page/endpoint assets from DB for this target."""
        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["url", "page", "endpoint"]),
            )
            result = await session.execute(stmt)
            seen: set[str] = set()
            urls: list[str] = []
            for asset in result.scalars().all():
                v = asset.asset_value
                if v and v not in seen:
                    seen.add(v)
                    urls.append(v)
        return urls

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, tool=self.name)

        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 0,
                "message": f"{self.name} started",
            })

            seed_urls = [
                u for u in await self._fetch_seed_urls(target_id)
                if scope_manager.is_in_scope(u).in_scope
            ]
            findings = await self._run_probes(seed_urls, headers or {})

            found = len(findings)
            new_count = in_scope_count = 0
            for finding in findings:
                inserted = await self._process_result(finding, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.utcnow()
                    await session.commit()

            stats = {
                "found": found,
                "in_scope": in_scope_count,
                "new": new_count,
                "skipped_cooldown": False,
            }
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 100,
                "message": (
                    f"{self.name}: {new_count} new, "
                    f"{in_scope_count} in scope, {found} total"
                ),
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()

    async def _run_probes(self, seed_urls: list[str], headers: dict) -> list[dict]:
        """Baseline each seed URL then probe all confused-path variants."""
        inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=10,
            headers=headers,
        ) as client:
            baseline_tasks = [
                self._baseline(client, inner_sem, url) for url in seed_urls
            ]
            baselines = await asyncio.gather(*baseline_tasks, return_exceptions=True)

            probe_tasks = []
            for seed_url, baseline in zip(seed_urls, baselines):
                if isinstance(baseline, Exception) or baseline is None:
                    continue
                for suffix in _CONFUSED_SUFFIXES:
                    confused_url = seed_url.rstrip("/") + "/x" + suffix
                    probe_tasks.append(
                        self._probe(client, inner_sem, seed_url, confused_url, baseline)
                    )

            probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        return [r for r in probe_results if r is not None and not isinstance(r, Exception)]

    async def _baseline(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        url: str,
    ) -> str | None:
        """GET the seed URL. Return body text (capped) if status 200, else None."""
        async with sem:
            try:
                resp = await client.get(url)
            except httpx.RequestError:
                return None
        if resp.status_code != 200:
            return None
        return resp.text[:_BODY_READ_LIMIT]

    async def _probe(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        seed_url: str,
        confused_url: str,
        baseline_body: str,
    ) -> dict | None:
        """GET the confused URL and compare to baseline body."""
        async with sem:
            try:
                resp = await client.get(confused_url)
            except httpx.RequestError:
                return None
        if resp.status_code != 200:
            return None
        return _analyze_confused_response(
            seed_url,
            confused_url,
            baseline_body,
            resp.text[:_BODY_READ_LIMIT],
            dict(resp.headers),
        )
