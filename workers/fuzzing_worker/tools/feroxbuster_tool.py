"""FeroxbusterTool — Stage 1 recursive content discovery."""
from __future__ import annotations
import json
import os
import tempfile

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore
from workers.fuzzing_worker.sensitive_patterns import check_sensitive

logger = setup_logger("feroxbuster-tool")

SMALL_WORDLIST = os.environ.get("WORDLIST_SMALL", "/app/wordlists/common.txt")
LARGE_WORDLIST = os.environ.get("WORDLIST_LARGE", "/app/wordlists/directory-list-2.3-medium.txt")
RATE_THRESHOLD = 50


class FeroxbusterTool(FuzzingTool):
    name = "feroxbuster"
    weight_class = WeightClass.HEAVY

    def _choose_wordlist(self, rate_limit: int) -> str:
        return LARGE_WORDLIST if rate_limit >= RATE_THRESHOLD else SMALL_WORDLIST

    def build_command(self, url: str, wordlist: str, rate_limit: int,
                      headers: dict | None = None, output_file: str = "/tmp/ferox.json") -> list[str]:
        cmd = [
            "feroxbuster", "-u", url, "-w", wordlist,
            "-o", output_file, "--json",
            "--status-codes", "200,204,301,302,307,401,403",
            "--rate-limit", str(rate_limit),
            "--threads", str(min(rate_limit, 50)),
            "--depth", "3",
        ]
        for k, v in (headers or {}).items():
            cmd.extend(["--headers", f"{k}: {v}"])
        return cmd

    def parse_output(self, raw: str) -> list[dict]:
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if "url" in entry:
                    results.append(entry)
            except json.JSONDecodeError:
                continue
        return results

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping feroxbuster — within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        discovered_dirs: list[str] = kwargs.get("discovered_dirs", [])
        if not discovered_dirs:
            log.info("No directories from ffuf — skipping feroxbuster")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)
        wordlist = self._choose_wordlist(rate_limit)

        sem = get_semaphore(self.weight_class)
        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        for dir_url in discovered_dirs:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                out_file = tmp.name

            cmd = self.build_command(dir_url, wordlist, rate_limit, headers, out_file)

            await sem.acquire()
            try:
                try:
                    await self.run_subprocess(cmd)
                except Exception as e:
                    log.error(f"feroxbuster failed on {dir_url}: {e}")
                    continue
                finally:
                    raw = ""
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

                saved_id = await self._save_asset(target_id, url, scope_manager, source_tool="feroxbuster")
                if saved_id is not None:
                    stats["in_scope"] += 1
                    stats["new"] += 1

                    sensitive = check_sensitive(url)
                    if sensitive:
                        await self._save_vulnerability(
                            target_id, saved_id, sensitive["severity"],
                            f"Sensitive file: {url}",
                            f"Category: {sensitive['category']}",
                            poc=url,
                        )

                    if status in (401, 403):
                        await self._save_vulnerability(
                            target_id, saved_id, "info",
                            "Access Restricted — potential bypass target",
                            f"HTTP {status} at {url}",
                        )

        await self.update_tool_state(target_id, container_name)
        log.info("feroxbuster complete", extra=stats)
        return stats
