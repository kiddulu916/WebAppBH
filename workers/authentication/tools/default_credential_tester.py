"""Default credential testing tool (WSTG-ATHN-02)."""
from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from lib_webbh import Asset, JobState, Vulnerability, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass, get_semaphore

logger = setup_logger("auth-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

_CAPTCHA_RE = re.compile(
    r"recaptcha|hcaptcha|h-captcha|turnstile|captcha\.js|g-recaptcha|cf-turnstile",
    re.IGNORECASE,
)
_LOCKOUT_RE = re.compile(
    r"too many|account.?lock|temporarily.?block|cooldown|rate.?limit",
    re.IGNORECASE,
)
_HYDRA_HIT_RE = re.compile(
    r"\[\d+\]\[[\w-]+\] host: \S+\s+login: (\S+)\s+password: (\S*)",
)

PAIRS_TOP10 = "/wordlists/auth/pairs_top10.txt"
PAIRS_TOP3 = "/wordlists/auth/pairs_top3.txt"
NUCLEI_COMMUNITY_DIR = "/nuclei-templates/community/http/default-logins/"
NUCLEI_CUSTOM_DIR = "/nuclei-templates/custom/"

DEFAULT_PATHS = [
    "/admin", "/admin/login", "/login", "/signin",
    "/wp-login.php", "/administrator",
    "/manager/html", "/console",
    "/phpmyadmin", "/pma", "/cpanel",
    "/dashboard", "/panel",
    "/j_security_check",
    "/api/login", "/api/v1/login",
]


class DefaultCredentialTester(AuthenticationTool):
    """Test for default credentials (WSTG-ATHN-02).

    Runs Nuclei default-logins templates as the primary engine, then falls back
    to conservative Hydra brute-force on URLs Nuclei did not hit.
    """

    name = "default_credential_tester"
    weight_class = WeightClass.HEAVY

    # Abstract contract stubs — execute() is fully overridden.
    def build_command(self, target, credentials=None) -> list[str]:
        return ["true"]

    def parse_output(self, stdout: str) -> list:
        return []

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def _load_settings(self, target_id: int) -> dict:
        config_dir = Path(f"/app/shared/config/{target_id}")
        return self._load_settings_from_dir(config_dir)

    def _load_settings_from_dir(self, config_dir: Path) -> dict:
        """Load and merge settings from config JSON files. Returns a flat settings dict."""
        def _read(name: str) -> dict:
            try:
                p = config_dir / name
                if p.exists():
                    return json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                pass
            return {}

        rate_limits = _read("rate_limits.json")
        custom_headers = _read("custom_headers.json")
        default_creds = _read("default_creds.json")

        pps = int(default_creds.get("nuclei_rate_limit") or rate_limits.get("pps", 10))
        hydra_wait = max(5, int(default_creds.get("hydra_wait_secs", 15)))
        proxy_pool = list(default_creds.get("proxy_pool", []))

        return {
            "pps": pps,
            "hydra_wait": hydra_wait,
            "proxy_pool": proxy_pool,
            "custom_headers": dict(custom_headers),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rotate_ip(self, pool: list[str], attempt: int) -> str | None:
        if not pool:
            return None
        return pool[attempt % len(pool)]

    def _is_captcha_protected(self, response_text: str) -> bool:
        return bool(_CAPTCHA_RE.search(response_text))

    def _has_lockout_signal(self, stdout: str) -> bool:
        return bool(_LOCKOUT_RE.search(stdout))

    def _select_hydra_pairs(self, lockout_threshold: int | None) -> str:
        if lockout_threshold is not None and lockout_threshold <= 5:
            return PAIRS_TOP3
        return PAIRS_TOP10

    # ------------------------------------------------------------------
    # URL discovery
    # ------------------------------------------------------------------

    async def _discover_urls(self, base_url: str, target_id: int) -> list[str]:
        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type == "admin_interface",
            )
            result = await session.execute(stmt)
            assets = result.scalars().all()

        if assets:
            return [a.asset_value for a in assets]

        found: list[str] = []
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=5.0) as client:
            for path in DEFAULT_PATHS:
                url = base_url.rstrip("/") + path
                try:
                    r = await client.get(url)
                    if r.status_code in (200, 401, 403):
                        found.append(url)
                except Exception:
                    pass
        return found

    async def _filter_captcha(self, urls: list[str]) -> list[str]:
        clean: list[str] = []
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0) as client:
            for url in urls:
                try:
                    r = await client.get(url)
                    if not self._is_captcha_protected(r.text):
                        clean.append(url)
                except Exception:
                    clean.append(url)
        return clean

    # ------------------------------------------------------------------
    # Nuclei phase
    # ------------------------------------------------------------------

    def _build_nuclei_cmd(
        self,
        urls_file: str,
        pps: int,
        custom_headers: dict,
        rotated_ip: str | None,
    ) -> list[str]:
        cmd = [
            "nuclei",
            "-l", urls_file,
            "-t", NUCLEI_COMMUNITY_DIR,
            "-t", NUCLEI_CUSTOM_DIR,
            "-rate-limit", str(pps),
            "-timeout", "10",
            "-retries", "1",
            "-silent",
            "-json",
            "-no-interactsh",
        ]
        if rotated_ip:
            cmd += ["-H", f"X-Forwarded-For: {rotated_ip}"]
        for key, val in custom_headers.items():
            cmd += ["-H", f"{key}: {val}"]
        return cmd

    def _parse_nuclei_jsonl(self, stdout: str) -> list[dict]:
        results: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = obj.get("template-id", "")
            matched_at = obj.get("matched-at", "")
            extracted = obj.get("extracted-results") or []

            username = extracted[0] if len(extracted) > 0 else ""
            password = extracted[1] if len(extracted) > 1 else ""

            results.append({
                "url": matched_at,
                "username": username,
                "password": password,
                "auth_type": "form",
                "template_id": template_id,
                "framework": template_id.split("-")[0] if template_id else None,
            })
        return results

    async def _run_nuclei(
        self,
        urls: list[str],
        settings: dict,
        attempt: int,
    ) -> tuple[list[dict], set[str]]:
        rotated_ip = self._rotate_ip(settings["proxy_pool"], attempt)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            urls_file = f.name

        try:
            cmd = self._build_nuclei_cmd(
                urls_file, settings["pps"], settings["custom_headers"], rotated_ip
            )
            try:
                stdout = await self.run_subprocess(cmd, timeout=TOOL_TIMEOUT)
            except (asyncio.TimeoutError, FileNotFoundError):
                return [], set()

            hits = self._parse_nuclei_jsonl(stdout)
            covered = {h["url"] for h in hits}
            return hits, covered
        finally:
            try:
                os.unlink(urls_file)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Hydra phase
    # ------------------------------------------------------------------

    def _build_hydra_cmd(
        self,
        url: str,
        pairs_file: str,
        hydra_wait: int,
        custom_headers: dict,
        rotated_ip: str | None,
        is_basic_auth: bool,
    ) -> list[str]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        scheme = parsed.scheme

        if is_basic_auth:
            module = "https-get" if scheme == "https" else "http-get"
            module_str = path
        else:
            module = "https-form-post" if scheme == "https" else "http-form-post"
            module_str = f"{path}:username=^USER^&password=^PASS^:F=invalid"
            if rotated_ip:
                module_str += f":H=X-Forwarded-For: {rotated_ip}"
            for key, val in custom_headers.items():
                module_str += f":H={key}: {val}"

        return [
            "hydra",
            "-C", pairs_file,
            "-t", "1",
            "-w", str(hydra_wait),
            "-f",
            "-s", str(port),
            host,
            module,
            module_str,
        ]

    def _parse_hydra_output(self, stdout: str, url: str, is_basic_auth: bool) -> list[dict]:
        results: list[dict] = []
        for match in _HYDRA_HIT_RE.finditer(stdout):
            username, password = match.group(1), match.group(2)
            results.append({
                "url": url,
                "username": username,
                "password": password,
                "auth_type": "basic" if is_basic_auth else "form",
                "template_id": None,
                "framework": None,
            })
        return results

    async def _get_lockout_threshold(self, target_id: int) -> int | None:
        async with get_session() as session:
            stmt = (
                select(Vulnerability)
                .where(
                    Vulnerability.target_id == target_id,
                    Vulnerability.source_tool == "lockout_tester",
                )
                .order_by(Vulnerability.id.desc())
                .limit(1)
            )
            result = await session.execute(stmt)
            vuln = result.scalar_one_or_none()

        if vuln and isinstance(vuln.evidence, dict):
            return vuln.evidence.get("lockout_at_attempt")
        return None

    async def _run_hydra_for_url(
        self,
        url: str,
        settings: dict,
        lockout_threshold: int | None,
        attempt: int,
    ) -> list[dict]:
        rotated_ip = self._rotate_ip(settings["proxy_pool"], attempt)
        pairs_file = self._select_hydra_pairs(lockout_threshold)
        is_basic_auth = False

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0) as client:
            try:
                r = await client.get(url)
                if self._is_captcha_protected(r.text):
                    return []
                is_basic_auth = "basic" in r.headers.get("www-authenticate", "").lower()
            except Exception:
                pass

        cmd = self._build_hydra_cmd(
            url=url,
            pairs_file=pairs_file,
            hydra_wait=settings["hydra_wait"],
            custom_headers=settings["custom_headers"],
            rotated_ip=rotated_ip,
            is_basic_auth=is_basic_auth,
        )
        try:
            stdout = await self.run_subprocess(cmd, timeout=TOOL_TIMEOUT)
        except (asyncio.TimeoutError, FileNotFoundError):
            return []

        if self._has_lockout_signal(stdout):
            return []

        return self._parse_hydra_output(stdout, url, is_basic_auth)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _save_hit(self, item: dict, target_id: int) -> None:
        title = (
            f"Default credentials accepted: {item['username']}/{item['password']} @ {item['url']}"
            if item.get("username")
            else item.get("title", "Default credential scan complete")
        )
        severity = "critical" if item.get("username") else "info"

        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                severity=severity,
                title=title,
                source_tool=self.name,
                section_id="4.2",
                worker_type="authentication",
                stage_name="default_credentials",
                evidence=item,
            )
            session.add(vuln)
            await session.commit()

        await push_task(f"events:{target_id}", {
            "event": "NEW_OBSERVATION",
            "target_id": target_id,
            "observation_type": "authentication",
            "title": title,
            "severity": severity,
            "source_tool": self.name,
        })

    # ------------------------------------------------------------------
    # execute()
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        credentials: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, asset_type="auth")

        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "inserted": 0, "skipped_cooldown": True}

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

            settings = self._load_settings(target_id)

            target_value = getattr(target, "target_value", str(target))
            base_url = (
                target_value
                if target_value.startswith(("http://", "https://"))
                else f"https://{target_value}"
            )

            urls = await self._discover_urls(base_url, target_id)
            if not urls:
                await self._save_hit({
                    "title": "No login paths found to test",
                    "url": base_url,
                    "username": "",
                    "password": "",
                    "auth_type": "summary",
                    "template_id": None,
                    "framework": None,
                }, target_id)
                return {"found": 0, "inserted": 1, "skipped_cooldown": False}

            urls = await self._filter_captcha(urls)
            urls = [u for u in urls if scope_manager.is_in_scope(u).in_scope]
            all_hits: list[dict] = []

            nuclei_hits, covered_urls = await self._run_nuclei(urls, settings, attempt=0)
            all_hits.extend(nuclei_hits)

            uncovered = [u for u in urls if u not in covered_urls]
            lockout_threshold = await self._get_lockout_threshold(target_id)

            for attempt, url in enumerate(uncovered):
                hydra_hits = await self._run_hydra_for_url(
                    url, settings, lockout_threshold, attempt
                )
                all_hits.extend(hydra_hits)

            for item in all_hits:
                await self._save_hit(item, target_id)

            # Always emit a summary observation so the stage shows activity
            await self._save_hit({
                "title": (
                    f"Default credentials test complete: {len(all_hits)} hit(s) "
                    f"across {len(urls)} path(s)"
                ),
                "url": base_url,
                "username": "",
                "password": "",
                "auth_type": "summary",
                "template_id": None,
                "framework": None,
                "urls_tested": len(urls),
                "hits": len(all_hits),
            }, target_id)

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
                "found": len(all_hits),
                "inserted": len(all_hits) + 1,
                "skipped_cooldown": False,
            }

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS",
                "container": container_name,
                "tool": self.name,
                "progress": 100,
                "message": f"{self.name}: {len(all_hits)} hit(s) found",
            })

            log.info(f"{self.name} complete", extra={"tool": self.name, **stats})
            return stats

        finally:
            sem.release()
