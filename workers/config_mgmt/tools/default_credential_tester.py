"""Default credential testing via Hydra (WSTG-CONF-01 pillar 3)."""

from __future__ import annotations

import asyncio
import os
import random
import re
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager
from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-tool")

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_PROFILES: dict[str, dict] = {
    "wordpress": {
        "paths": ["/wp-admin", "/wp-login.php"],
        "users": ["admin", "administrator"],
        "passwords": ["admin", "password", "wordpress", "123456"],
        "module": "http-form-post",
        "failure_string": "is wrong",
    },
    "tomcat": {
        "paths": ["/manager/html", "/host-manager/html"],
        "users": ["tomcat", "admin", "manager"],
        "passwords": ["tomcat", "s3cret", "manager", "admin"],
        "module": "http-get",
        "failure_string": "401",
    },
    "solr": {
        "paths": ["/solr"],
        "users": ["solr"],
        "passwords": ["SolrRocks", "admin", "solr"],
        "module": "http-get",
        "failure_string": "Unauthorized",
    },
    "jenkins": {
        "paths": ["/jenkins"],
        "users": ["admin", "jenkins"],
        "passwords": ["admin", "jenkins", "password"],
        "module": "http-form-post",
        "failure_string": "Invalid username or password",
    },
    "kibana": {
        "paths": ["/kibana"],
        "users": ["elastic", "kibana"],
        "passwords": ["changeme", "elastic"],
        "module": "http-form-post",
        "failure_string": "Invalid username or password",
    },
    "generic": {
        "paths": [],
        "users": ["admin", "root", "administrator"],
        "passwords": ["admin", "password", "123456", "root", "admin123"],
        "module": "http-form-post",
        "failure_string": "invalid",
    },
}

_SUCCESS_RE = re.compile(r"\[\d+\]\[[\w-]+\] host: \S+\s+login: (\S+)\s+password: (\S+)")


class DefaultCredentialTester(ConfigMgmtTool):
    """Test default credentials on admin interfaces discovered by AdminInterfaceFinder."""

    name = "default_credential_tester"
    _USER_AGENTS = _USER_AGENTS

    def build_command(self, target, headers=None) -> list[str]:
        # Satisfies the abstract contract; execute() is fully overridden.
        return ["true"]

    def parse_output(self, stdout: str) -> list:
        # Satisfies the abstract contract; execute() is fully overridden.
        return []

    def _get_profile(self, path: str) -> dict:
        for name, profile in _PROFILES.items():
            if name == "generic":
                continue
            if any(path.startswith(p) for p in profile["paths"]):
                return profile
        return _PROFILES["generic"]

    def _build_hydra_command(
        self,
        host: str,
        port: int,
        path: str,
        userlist_path: str,
        passlist_path: str,
        jitter: int,
        ua: str,
        failure_string: str,
        module: str,
    ) -> list[str]:
        if module == "http-get":
            module_str = path
        else:
            module_str = f"{path}:user=^USER^&pass=^PASS^:F={failure_string}:H=User-Agent: {ua}"
        return [
            "hydra",
            "-L", userlist_path,
            "-P", passlist_path,
            "-t", "1",
            "-f",
            "-w", str(jitter),
            "-s", str(port),
            host,
            module,
            module_str,
        ]

    def _parse_hydra_output(self, stdout: str, url: str) -> list:
        results = []
        successes = _SUCCESS_RE.findall(stdout)
        for login, password in successes:
            results.append({"vulnerability": {
                "name": f"Default credentials found at {url}",
                "severity": "critical",
                "description": f"Login succeeded with username '{login}' and password '{password}'",
                "location": url,
            }})
        outcome = "credentials_found" if successes else "no_credentials_found"
        results.append({"observation": {
            "type": "credential_test_result",
            "value": url,
            "details": {"url": url, "outcome": outcome, "credentials_found": len(successes)},
        }})
        return results

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

            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "admin_interface",
                    Asset.source_tool == "admin_interface_finder",
                )
                result = await session.execute(stmt)
                admin_interfaces = result.scalars().all()

            if not admin_interfaces:
                log.info(f"{self.name}: no admin interfaces to test, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            cred_rate_limit = int(os.environ.get("CONF_CRED_RATE_LIMIT", "3"))
            all_results = []

            for asset in admin_interfaces:
                url = asset.asset_value
                path = urlparse(url).path or "/admin"

                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)

                profile = self._get_profile(path)
                jitter = int(random.uniform(cred_rate_limit, cred_rate_limit * 2.5))
                ua = random.choice(self._USER_AGENTS)

                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
                    uf.write("\n".join(profile["users"]))
                    userlist_path = uf.name
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
                    pf.write("\n".join(profile["passwords"]))
                    passlist_path = pf.name

                try:
                    cmd = self._build_hydra_command(
                        host=host, port=port, path=path,
                        userlist_path=userlist_path, passlist_path=passlist_path,
                        jitter=jitter, ua=ua,
                        failure_string=profile["failure_string"],
                        module=profile["module"],
                    )
                    try:
                        stdout = await self.run_subprocess(cmd)
                        all_results.extend(self._parse_hydra_output(stdout, url))
                    except (asyncio.TimeoutError, FileNotFoundError) as exc:
                        log.warning(f"{self.name}: hydra failed for {url} — {exc}")
                finally:
                    for tmp in (userlist_path, passlist_path):
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass

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
