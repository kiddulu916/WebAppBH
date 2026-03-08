"""ExtensionFuzzTool — Stage 1 backup/leftover file permutation fuzzing."""
from __future__ import annotations
import json
import os
import tempfile

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore
from workers.fuzzing_worker.sensitive_patterns import check_sensitive

logger = setup_logger("extension-fuzz-tool")

DYNAMIC_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb",
    ".js", ".json", ".xml", ".conf", ".yml", ".yaml",
}

BACKUP_EXTENSIONS = [".bak", ".old", ".swp", ".orig", "~", ".temp", ".save", ".dist"]


class ExtensionFuzzTool(FuzzingTool):
    name = "ffuf-ext"
    weight_class = WeightClass.LIGHT

    def filter_dynamic_files(self, urls: list[str]) -> list[str]:
        result = []
        for url in urls:
            filename = url.rsplit("/", 1)[-1]
            _, dot, ext = filename.rpartition(".")
            if dot and f".{ext}" in DYNAMIC_EXTENSIONS:
                result.append(url)
        return result

    def generate_variants(self, url: str) -> list[str]:
        variants = []
        for ext in BACKUP_EXTENSIONS:
            variants.append(f"{url}{ext}")
        # Vim swap: /path/.filename.swp
        parts = url.rsplit("/", 1)
        if len(parts) == 2:
            base, filename = parts
            variants.append(f"{base}/.{filename}.swp")
        return variants

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping extension fuzz — within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        discovered_files: list[str] = kwargs.get("discovered_files", [])
        dynamic_files = self.filter_dynamic_files(discovered_files)

        if not dynamic_files:
            log.info("No dynamic files to permute")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)

        all_variants: list[str] = []
        for url in dynamic_files:
            all_variants.extend(self.generate_variants(url))

        if not all_variants:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wl_file:
            wl_file.write("\n".join(all_variants))
            wl_path = wl_file.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_file = tmp.name

        cmd = [
            "ffuf", "-u", "FUZZ", "-w", wl_path,
            "-o", out_file, "-of", "json",
            "-mc", "200,204,301,302,307",
            "-rate", str(rate_limit),
        ]
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])

        sem = get_semaphore(self.weight_class)
        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        await sem.acquire()
        try:
            try:
                await self.run_subprocess(cmd)
            except Exception as e:
                log.error(f"ffuf extension fuzz failed: {e}")
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
            url = entry.get("url", "")
            stats["found"] += 1

            saved_id = await self._save_asset(target_id, url, scope_manager, source_tool="ffuf-ext")
            if saved_id is not None:
                stats["in_scope"] += 1
                stats["new"] += 1

                sensitive = check_sensitive(url)
                if sensitive:
                    await self._save_vulnerability(
                        target_id, saved_id, sensitive["severity"],
                        f"Backup file found: {url}",
                        f"Category: {sensitive['category']}",
                        poc=url,
                    )

        await self.update_tool_state(target_id, container_name)
        log.info("extension fuzz complete", extra=stats)
        return stats
