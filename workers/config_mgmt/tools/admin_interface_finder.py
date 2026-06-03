"""Admin interface and infrastructure discovery (WSTG-CONF-01 pillar 2)."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager
from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-tool")

ADMIN_PORTS = {21, 161, 445, 623, 2049, 6379, 8080, 8443, 8888, 9200, 9300, 27017, 5432, 3306, 1433}

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin/login", "/manage", "/manager",
    "/console", "/server-status", "/nginx_status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env",
    "/manager/html", "/host-manager/html",
    "/wp-admin", "/wp-login.php", "/administrator/index.php", "/admin.php",
    "/phpmyadmin", "/pma", "/cpanel", "/webmin", "/kibana", "/solr",
    "/jenkins", "/grafana",
    "/.env", "/config.php", "/web.config", "/.git/HEAD",
]


class AdminInterfaceFinder(ConfigMgmtTool):
    """Discover admin interfaces via nmap port scan and HTTP path probing."""

    name = "admin_interface_finder"

    def _extract_host(self, target) -> str:
        value = getattr(target, "target_value", str(target))
        if "://" in value:
            return urlparse(value).hostname or value
        return value.split(":")[0]

    def _extract_base_url(self, target) -> str:
        value = getattr(target, "target_value", str(target))
        if value.startswith(("http://", "https://")):
            return value
        return f"https://{value}"

    def build_command(self, target, headers=None) -> list[str]:
        host = self._extract_host(target)
        ports = ",".join(str(p) for p in sorted(ADMIN_PORTS | {80, 443, 8000, 8001, 8008, 8009, 8443, 9090}))
        return ["nmap", f"-p{ports}", "-sV", "--open", "--host-timeout", "60s", "-oG", "-", host]

    def _parse_nmap_output(self, stdout: str) -> list:
        results = []
        port_re = re.compile(r"(\d+)/(open)/(tcp|udp)//([^/]*)//([^/]*)")
        for line in stdout.splitlines():
            if not line.startswith("Host:"):
                continue
            for m in port_re.finditer(line):
                port = int(m.group(1))
                proto = m.group(3)
                service = m.group(4).strip()
                banner = m.group(5).strip()
                results.append({"observation": {
                    "type": "open_service",
                    "value": f"{port}/{proto}",
                    "details": {
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "banner": banner,
                        "is_admin_service": port in ADMIN_PORTS,
                    },
                }})
        return results

    def _build_http_probe_command(self, base_url: str) -> list[str]:
        paths_json = json.dumps(ADMIN_PATHS)
        script = f"""
import httpx, json
results = []
base_url = {json.dumps(base_url)}
paths = {paths_json}
try:
    client = httpx.Client(follow_redirects=False, timeout=8, verify=False)
    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                results.append({{"observation": {{"type": "admin_interface", "value": url, "details": {{"path": path, "status": 200, "content_length": len(resp.content), "server": resp.headers.get("server", "")}}}}}})
            elif resp.status_code in (301, 302, 307, 308):
                results.append({{"observation": {{"type": "admin_redirect", "value": url, "details": {{"path": path, "status": resp.status_code, "redirect_to": resp.headers.get("location", "")}}}}}})
        except Exception:
            pass
    client.close()
except Exception as e:
    results.append({{"observation": {{"type": "test_error", "value": str(e), "details": {{"error": str(e)}}}}}})
print(json.dumps(results))
"""
        return ["python3", "-c", script]

    def parse_output(self, stdout: str) -> list:
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, asset_type="job")

        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0, "message": f"{self.name} started",
            })

            all_results = []

            # Phase A: nmap full-range port scan
            try:
                nmap_stdout = await self.run_subprocess(self.build_command(target, headers))
                all_results.extend(self._parse_nmap_output(nmap_stdout))
            except (asyncio.TimeoutError, FileNotFoundError) as exc:
                log.warning(f"{self.name}: nmap phase failed — {exc}")

            # Phase B: HTTP admin path probing
            try:
                http_stdout = await self.run_subprocess(
                    self._build_http_probe_command(self._extract_base_url(target))
                )
                all_results.extend(self.parse_output(http_stdout))
            except (asyncio.TimeoutError, FileNotFoundError):
                log.warning(f"{self.name}: HTTP probe timed out")

            found = len(all_results)
            new_count = 0
            in_scope_count = 0
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
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
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

            log.info(f"{self.name} complete", extra={"tool": self.name, **stats})
            return stats

        finally:
            sem.release()
