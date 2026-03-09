"""ArjunTool — Stage 3 HTTP parameter discovery."""
from __future__ import annotations
import json
import os
import tempfile

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("arjun-tool")

HIGH_VALUE_PARAMS = {
    "debug", "admin", "test", "load_config", "proxy",
    "callback", "token", "secret",
}


class ArjunTool(FuzzingTool):
    name = "arjun"
    weight_class = WeightClass.HEAVY

    def build_command(self, url: str, rate_limit: int,
                      headers: dict | None = None,
                      output_file: str = "/tmp/arjun.json") -> list[str]:
        delay_ms = max(1, int(1000 / rate_limit)) if rate_limit > 0 else 100
        cmd = [
            "arjun", "-u", url,
            "-oJ", output_file,
            "--stable",
            "--delay", str(delay_ms),
        ]
        if headers:
            header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
            cmd.extend(["--headers", header_str])
        return cmd

    def parse_output(self, raw: str) -> list[dict]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        results = []
        for url, methods in data.items():
            for method, params in methods.items():
                for param in params:
                    results.append({"url": url, "method": method, "param_name": param})
        return results

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping arjun — within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        url_assets = await self._get_all_url_assets(target_id)
        if not url_assets:
            log.info("No URL assets to probe for parameters")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)

        sem = get_semaphore(self.weight_class)
        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        for asset_id, url in url_assets:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                out_file = tmp.name

            cmd = self.build_command(url, rate_limit, headers, out_file)

            await sem.acquire()
            try:
                try:
                    await self.run_subprocess(cmd)
                except Exception as e:
                    log.error(f"arjun failed on {url}: {e}")
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
                param_name = entry["param_name"]
                new = await self._save_parameter(asset_id, param_name, "", url)
                if new:
                    stats["new"] += 1
                    stats["in_scope"] += 1

                    if param_name.lower() in HIGH_VALUE_PARAMS:
                        await self._save_vulnerability(
                            target_id, asset_id, "high",
                            f"High-value parameter: {param_name} on {url}",
                            f"Hidden {entry['method']} parameter '{param_name}' discovered via Arjun",
                        )

        await self.update_tool_state(target_id, container_name)
        log.info("arjun complete", extra=stats)
        return stats
