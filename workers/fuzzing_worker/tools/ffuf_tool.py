"""FfufTool — Stage 1 flat directory fuzzing with ffuf."""
from __future__ import annotations
import json
import os
import tempfile

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore
from workers.fuzzing_worker.sensitive_patterns import check_sensitive

logger = setup_logger("ffuf-tool")

SMALL_WORDLIST = os.environ.get("WORDLIST_SMALL", "/app/wordlists/common.txt")
LARGE_WORDLIST = os.environ.get("WORDLIST_LARGE", "/app/wordlists/directory-list-2.3-medium.txt")
RATE_THRESHOLD = 50


class FfufTool(FuzzingTool):
    name = "ffuf"
    weight_class = WeightClass.HEAVY

    def _choose_wordlist(self, rate_limit: int) -> str:
        return LARGE_WORDLIST if rate_limit >= RATE_THRESHOLD else SMALL_WORDLIST

    def build_command(self, url: str, wordlist: str, rate_limit: int,
                      headers: dict | None = None, output_file: str = "/tmp/ffuf.json") -> list[str]:
        cmd = [
            "ffuf", "-u", url, "-w", wordlist,
            "-o", output_file, "-of", "json",
            "-mc", "200,204,301,302,307,401,403",
            "-rate", str(rate_limit),
            "-t", str(min(rate_limit, 50)),
        ]
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])
        return cmd

    def parse_output(self, raw: str) -> list[dict]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return data.get("results", [])

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping ffuf — within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)
        wordlist = self._choose_wordlist(rate_limit)
        discovered_dirs: list[str] = []

        sem = get_semaphore(self.weight_class)
        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        for asset_id, domain in urls:
            base_url = f"https://{domain}"
            fuzz_url = f"{base_url}/FUZZ"

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                out_file = tmp.name

            cmd = self.build_command(fuzz_url, wordlist, rate_limit, headers, out_file)

            await sem.acquire()
            try:
                try:
                    raw = await self.run_subprocess(cmd)
                except Exception as e:
                    log.error(f"ffuf failed on {domain}: {e}")
                    continue
                finally:
                    if os.path.exists(out_file):
                        with open(out_file) as f:
                            raw = f.read()
                        os.unlink(out_file)
            finally:
                sem.release()

            results = self.parse_output(raw)
            stats["found"] += len(results)

            for entry in results:
                url = entry.get("url", "")
                status = entry.get("status", 0)

                saved_id = await self._save_asset(target_id, url, scope_manager, source_tool="ffuf")
                if saved_id is not None:
                    stats["in_scope"] += 1
                    stats["new"] += 1

                    # Track directories for feroxbuster handoff
                    if status in (200, 301, 302) and not url.rsplit("/", 1)[-1].count("."):
                        discovered_dirs.append(url)

                    # Check sensitive patterns
                    sensitive = check_sensitive(url)
                    if sensitive:
                        await self._save_vulnerability(
                            target_id, saved_id, sensitive["severity"],
                            f"Sensitive file: {url}",
                            f"Category: {sensitive['category']}. Matched pattern: {sensitive['pattern']}",
                            poc=url,
                        )

                    # Flag 401/403 for webapp worker
                    if status in (401, 403):
                        await self._save_vulnerability(
                            target_id, saved_id, "info",
                            "Access Restricted — potential bypass target",
                            f"HTTP {status} at {url}",
                        )

        # Store discovered dirs for feroxbuster (via kwargs side-channel)
        kwargs_store = kwargs.get("shared_state")
        if kwargs_store is not None:
            kwargs_store["discovered_dirs"] = discovered_dirs

        await self.update_tool_state(target_id, container_name)
        log.info("ffuf complete", extra=stats)
        return stats
