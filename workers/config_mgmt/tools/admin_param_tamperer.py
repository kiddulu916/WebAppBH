"""Admin parameter tampering tool — WSTG-CONF-05."""

from __future__ import annotations

import asyncio
from datetime import datetime

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf05")

_HTTP_CONCURRENCY = 10
_SECTION_ID = "WSTG-CONF-05"

_ADMIN_PARAM_PATTERNS = frozenset({
    "admin", "useradmin", "is_admin", "isadmin", "administrator",
    "role", "user_type", "usertype", "access", "privilege", "level",
    "debug", "test", "dev", "development", "staff", "superuser",
    "su", "root", "authorized", "auth", "authenticated",
})

_FLIP_MAP: dict[str, str] = {
    "0": "1",
    "false": "true",
    "no": "yes",
    "user": "admin",
    "guest": "admin",
    "readonly": "admin",
}

_ADMIN_BODY_KEYWORDS = frozenset({
    "dashboard", "panel", "settings", "users", "configuration",
    "logout", "welcome", "administrator", "manage", "control",
})


def _extract_hidden_inputs(html: str) -> list[tuple[str, str]]:
    """Return list of (name, value) pairs for all hidden input fields."""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []
    result = []
    for inp in soup.find_all("input"):
        if str(inp.get("type", "")).lower() == "hidden":
            name = inp.get("name", "")
            value = inp.get("value", "") or ""
            if name:
                result.append((name, value))
    return result


def _filter_admin_params(
    params: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Keep only params whose name contains a suspicious admin-related keyword."""
    result = []
    for name, value in params:
        name_lower = name.lower()
        if any(kw in name_lower for kw in _ADMIN_PARAM_PATTERNS):
            result.append((name, value))
    return result


def _build_flip_values(value: str) -> list[str]:
    """Return candidate replacement values to probe for this parameter."""
    lower = value.lower().strip()
    if lower in _FLIP_MAP:
        return [_FLIP_MAP[lower], "admin", "1"]
    return ["admin", "1", "true", "yes"]


def _classify_tamper_response(
    baseline_status: int,
    new_status: int,
    baseline_len: int,
    new_len: int,
    new_body: str,
    baseline_body: str = "",
) -> tuple[str | None, str | None]:
    """Return (severity, vuln_type) if the tampered response differs meaningfully.

    Returns (None, None) if no significant change detected.
    """
    if baseline_status in (403, 302, 401) and new_status == 200:
        return "critical", "parameter_tampering_bypass"

    new_body_lower = new_body.lower()
    baseline_body_lower = baseline_body.lower()
    if any(kw in new_body_lower for kw in _ADMIN_BODY_KEYWORDS) and not any(kw in baseline_body_lower for kw in _ADMIN_BODY_KEYWORDS):
        return "high", "parameter_tampering_escalation"

    if baseline_len > 0 and abs(new_len - baseline_len) / baseline_len > 0.20:
        return "medium", "parameter_tampering_indicator"

    return None, None


class AdminParamTamperer(ConfigMgmtTool):
    """Test parameter tampering on discovered admin interfaces. WSTG-CONF-05."""

    name = "admin_param_tamperer"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("AdminParamTamperer uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("AdminParamTamperer uses execute() directly")

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
            log.info("Skipping — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0,
                "message": f"{self.name} started",
            })

            # Scope check
            base_url = target.target_value if hasattr(target, "target_value") else str(target)
            if not base_url.startswith(("http://", "https://")):
                base_url = f"https://{base_url.rstrip('/')}"
            else:
                base_url = base_url.rstrip("/")

            scope_result = scope_manager.is_in_scope(base_url)
            if not scope_result.in_scope:
                log.info(f"{self.name}: target out of scope, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # Phase 0 — DB reads
            async with get_session() as session:
                stmt = select(Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["admin_interface", "admin_redirect"]),
                    Asset.source_tool.in_([
                        "admin_interface_finder",
                        "admin_interface_enumerator",
                    ]),
                )
                rows = (await session.execute(stmt)).scalars().all()
                urls = list(rows)

            if not urls:
                log.info(f"{self.name}: no admin interfaces in DB — skipping")
                await push_task(f"events:{target_id}", {
                    "event": "TOOL_PROGRESS", "container": container_name,
                    "tool": self.name, "progress": 100,
                    "message": f"{self.name}: no targets found",
                })
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            all_results: list[dict] = []
            inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)

            client_kwargs = dict(
                verify=False, follow_redirects=False, timeout=10,
                headers=headers or {},
            )

            async def _tamper_url(client: httpx.AsyncClient, url: str) -> list[dict]:
                results: list[dict] = []
                async with inner_sem:
                    try:
                        base_resp = await client.get(url)
                        baseline_status = base_resp.status_code
                        baseline_body = base_resp.text
                        baseline_len = len(baseline_body)

                        params = _filter_admin_params(
                            _extract_hidden_inputs(baseline_body)
                        )

                        for cname, cvalue in base_resp.cookies.items():
                            params.extend(_filter_admin_params([(cname, cvalue or "")]))

                        for param_name, param_value in params:
                            for flip in _build_flip_values(param_value):
                                try:
                                    tampered = await client.get(
                                        url, params={param_name: flip}
                                    )
                                    severity, vuln_type = _classify_tamper_response(
                                        baseline_status=baseline_status,
                                        new_status=tampered.status_code,
                                        baseline_len=baseline_len,
                                        new_len=len(tampered.text),
                                        new_body=tampered.text,
                                        baseline_body=baseline_body,
                                    )
                                    if severity:
                                        results.append({"vulnerability": {
                                            "name": f"Parameter tampering on {param_name}: {url}",
                                            "severity": severity,
                                            "description": (
                                                f"Setting {param_name}={flip} on {url} "
                                                f"changed response from HTTP {baseline_status} "
                                                f"to HTTP {tampered.status_code}."
                                            ),
                                            "location": url,
                                            "section_id": _SECTION_ID,
                                        }})
                                        break
                                except httpx.RequestError:
                                    pass
                    except httpx.RequestError:
                        pass
                return results

            async with httpx.AsyncClient(**client_kwargs) as client:
                tasks = [_tamper_url(client, url) for url in urls]
                gathered = await asyncio.gather(*tasks, return_exceptions=True)
                for r in gathered:
                    if isinstance(r, list):
                        all_results.extend(r)

            found = len(all_results)
            new_count = in_scope_count = 0
            for item in all_results:
                inserted = await self._process_result(item, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                job = (await session.execute(stmt)).scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.utcnow()
                    await session.commit()

            stats = {"found": found, "in_scope": in_scope_count, "new": new_count, "skipped_cooldown": False}
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": f"{self.name}: {new_count} new, {in_scope_count} in scope, {found} total",
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()
