"""SSRFmapTool -- Server-Side Request Forgery detection via SSRFmap."""

from __future__ import annotations

import os
import tempfile
from urllib.parse import urlparse

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore

logger = setup_logger("ssrfmap-tool")

SSRF_TIMEOUT = int(os.environ.get("SSRF_TIMEOUT", "180"))

# Common parameter names associated with SSRF
SSRF_PARAMS = frozenset([
    "url", "redirect", "proxy", "callback", "next", "return",
    "dest", "uri", "path", "forward", "target", "rurl", "src", "href",
])


class SSRFmapTool(VulnScanTool):
    """Server-Side Request Forgery scanning via SSRFmap."""

    name = "ssrfmap"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_request_file(url: str, param: str, headers: dict | None = None) -> str:
        """Create a raw HTTP request file for SSRFmap and return its path."""
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        query = parsed.query

        # Build GET request with the target parameter
        request_lines = [
            f"GET {path}?{query} HTTP/1.1" if query else f"GET {path}?{param}=SSRF HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0",
            "Accept: */*",
        ]
        if headers:
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
        request_lines.append("")
        request_lines.append("")

        fd, path = tempfile.mkstemp(prefix="ssrfmap-req-", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("\r\n".join(request_lines))
        return path

    @staticmethod
    def _is_ssrf_indicator(stdout: str) -> bool:
        """Check if SSRFmap stdout indicates a vulnerability."""
        for line in stdout.splitlines():
            low = line.lower()
            if "retrieved" in low or "response" in low or "internal" in low:
                return True
            # Check for cloud metadata endpoint access
            if "169.254.169.254" in line:
                return True
        return False

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)
        triaged_findings = kwargs.get("triaged_findings")
        scan_all = kwargs.get("scan_all", False)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping ssrfmap -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
        sem = get_semaphore(self.weight_class)

        if triaged_findings:
            # -- Stage 2: confirm specific SSRF findings --
            for vuln_id, asset_id, severity, title, poc in triaged_findings:
                target_url = poc or ""
                if not target_url.startswith("http"):
                    continue

                # Try to extract param from URL query string
                parsed = urlparse(target_url)
                param_name = None
                if parsed.query:
                    for part in parsed.query.split("&"):
                        if "=" in part:
                            pname = part.split("=", 1)[0].lower()
                            if pname in SSRF_PARAMS:
                                param_name = pname
                                break
                    # If no SSRF param found, use the first param
                    if not param_name and "=" in parsed.query:
                        param_name = parsed.query.split("=", 1)[0].split("&")[0]

                if not param_name:
                    param_name = "url"

                req_file = self._build_request_file(target_url, param_name, headers)
                try:
                    cmd = [
                        "python3", "/opt/SSRFmap/ssrfmap.py",
                        "-r", req_file,
                        "-p", param_name,
                        "-m", "readfiles",
                    ]

                    async with sem:
                        try:
                            stdout = await self.run_subprocess(cmd, timeout=SSRF_TIMEOUT)
                        except Exception as exc:
                            log.error(f"SSRFmap failed for {target_url}: {exc}")
                            continue

                    if self._is_ssrf_indicator(stdout):
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        await self._update_vulnerability(
                            vuln_id=vuln_id,
                            severity=severity,
                            poc=f"SSRFmap confirmed:\n{stdout[:500]}",
                            source_tool="ssrfmap",
                            description=f"SSRFmap confirmed SSRF vulnerability: {title}",
                        )
                        log.info(f"SSRFmap confirmed SSRF at {target_url}")
                finally:
                    try:
                        os.unlink(req_file)
                    except OSError:
                        pass

        elif scan_all:
            # -- Stage 3: broad SSRF sweep --
            all_params = await self._get_all_parameters(target_id)

            # Filter to SSRF-relevant parameter names
            ssrf_targets: list[tuple[int, str, str, str | None]] = []
            for asset_id, param_name, param_value, source_url in all_params:
                if param_name.lower() in SSRF_PARAMS:
                    ssrf_targets.append((asset_id, param_name, param_value or "", source_url or ""))

            for asset_id, param_name, _param_value, source_url in ssrf_targets:
                if not source_url or not source_url.startswith("http"):
                    continue

                if await self._has_confirmed_vuln(target_id, asset_id, "ssrf"):
                    log.debug(f"Skipping {source_url} -- already confirmed SSRF")
                    continue

                req_file = self._build_request_file(source_url, param_name, headers)
                try:
                    cmd = [
                        "python3", "/opt/SSRFmap/ssrfmap.py",
                        "-r", req_file,
                        "-p", param_name,
                        "-m", "readfiles",
                    ]

                    async with sem:
                        try:
                            stdout = await self.run_subprocess(cmd, timeout=SSRF_TIMEOUT)
                        except Exception as exc:
                            log.error(f"SSRFmap failed for {source_url} param={param_name}: {exc}")
                            continue

                    if self._is_ssrf_indicator(stdout):
                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title=f"Server-Side Request Forgery ({param_name}) - {source_url}",
                            description=f"SSRFmap detected SSRF via param '{param_name}' at {source_url}",
                            poc=stdout[:500],
                        )
                        log.info(f"SSRFmap found SSRF at {source_url} param={param_name}")
                finally:
                    try:
                        os.unlink(req_file)
                    except OSError:
                        pass
        else:
            log.info("No triaged findings or scan_all -- skipping")
            return stats

        await self.update_tool_state(target_id, container_name)
        log.info("ssrfmap complete", extra=stats)
        return stats
