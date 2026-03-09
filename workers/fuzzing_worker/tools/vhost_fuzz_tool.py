"""VhostFuzzTool — Stage 2 virtual host discovery via ffuf."""
from __future__ import annotations
import json
import os
import socket
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, Location, get_session, setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore
from workers.fuzzing_worker.permutation import extract_prefix

logger = setup_logger("vhost-fuzz-tool")

DNS_WORDLIST = os.environ.get("VHOST_WORDLIST", "/app/wordlists/subdomains-top1million-5000.txt")

SENSITIVE_VHOST_KEYWORDS = {"admin", "internal", "staging", "debug", "dev", "test"}


class VhostFuzzTool(FuzzingTool):
    name = "ffuf-vhost"
    weight_class = WeightClass.HEAVY

    def build_wordlist(self, existing_prefixes: list[str]) -> list[str]:
        combined: set[str] = set(existing_prefixes)
        if os.path.exists(DNS_WORDLIST):
            with open(DNS_WORDLIST) as f:
                for line in f:
                    word = line.strip()
                    if word:
                        combined.add(word)
        return sorted(combined)

    def build_command(self, ip: str, base_domain: str, wordlist: str,
                      rate_limit: int, baseline_size: int,
                      headers: dict | None = None,
                      output_file: str = "/tmp/vhost.json") -> list[str]:
        cmd = [
            "ffuf", "-u", f"https://{ip}",
            "-H", f"Host: FUZZ.{base_domain}",
            "-w", wordlist,
            "-o", output_file, "-of", "json",
            "-fs", str(baseline_size),
            "-rate", str(rate_limit),
            "-t", str(min(rate_limit, 50)),
        ]
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])
        return cmd

    async def _resolve_ip(self, domain: str) -> str | None:
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    async def _get_baseline_size(self, ip: str, base_domain: str) -> int:
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{ip}",
                    headers={"Host": f"nonexistent-baseline-{os.urandom(4).hex()}.{base_domain}"},
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.read()
                    return len(body)
        except Exception:
            return 0

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping vhost fuzz — within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)
        base_domain = target.base_domain

        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id, Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        existing_prefixes = []
        for d in domains:
            prefix = extract_prefix(d, base_domain)
            if prefix:
                existing_prefixes.append(prefix)

        wordlist_entries = self.build_wordlist(existing_prefixes)
        if not wordlist_entries:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wl_file:
            wl_file.write("\n".join(wordlist_entries))
            wl_path = wl_file.name

        ip = await self._resolve_ip(base_domain)
        if not ip:
            log.error(f"Cannot resolve {base_domain}")
            os.unlink(wl_path)
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        baseline_size = await self._get_baseline_size(ip, base_domain)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_file = tmp.name

        cmd = self.build_command(ip, base_domain, wl_path, rate_limit, baseline_size, headers, out_file)

        sem = get_semaphore(self.weight_class)
        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        await sem.acquire()
        try:
            try:
                await self.run_subprocess(cmd)
            except Exception as e:
                log.error(f"vhost fuzz failed: {e}")
                return stats
            finally:
                raw = ""
                if os.path.exists(out_file):
                    with open(out_file) as f:
                        raw = f.read()
                    os.unlink(out_file)
                if os.path.exists(wl_path):
                    os.unlink(wl_path)
        finally:
            sem.release()

        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            data = {}

        for entry in data.get("results", []):
            fuzz_val = entry.get("input", {}).get("FUZZ", "")
            vhost = f"{fuzz_val}.{base_domain}"

            saved_id = await self._save_asset(target_id, vhost, scope_manager, source_tool="ffuf-vhost")
            if saved_id is not None:
                stats["in_scope"] += 1
                stats["new"] += 1
                stats["found"] += 1

                async with get_session() as session:
                    loc = Location(asset_id=saved_id, port=443,
                                   protocol="tcp", service="https", state="open")
                    session.add(loc)
                    await session.commit()

                if any(kw in fuzz_val.lower() for kw in SENSITIVE_VHOST_KEYWORDS):
                    await self._save_vulnerability(
                        target_id, saved_id, "high",
                        f"Sensitive virtual host: {vhost}",
                        f"Hidden vhost discovered via Host header fuzzing",
                        poc=f"curl -H 'Host: {vhost}' https://{ip}",
                    )

        await self.update_tool_state(target_id, container_name)
        log.info("vhost fuzz complete", extra=stats)
        return stats
