"""PostgreSQL-specific SQL injection testing using sqlmap."""

from __future__ import annotations

from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class SqlmapPostgresTool(InputValidationTool):
    """Test for PostgreSQL SQL injection vulnerabilities using sqlmap."""

    name = "sqlmap_postgres"
    weight_class = WeightClass.HEAVY

    def build_command(self, target: str, headers: dict | None = None) -> list[str]:
        """Build the sqlmap command for PostgreSQL injection testing."""
        cmd = ["sqlmap", "-u", target, "--dbms=PostgreSQL", "--batch", "--random-agent"]
        if headers:
            for key, value in headers.items():
                cmd.extend(["--headers", f"{key}: {value}"])
        return cmd

    def parse_output(self, stdout: str) -> list[dict]:
        """Parse sqlmap output for PostgreSQL injection results."""
        results = []
        return results

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Execute PostgreSQL injection tests against target URLs."""
        found = 0
        vulnerable = 0

        urls = await self._get_all_url_assets(target_id)

        for asset_id, url in urls:
            cmd = self.build_command(url, headers)
            try:
                stdout = await self.run_subprocess(cmd)
                parsed = self.parse_output(stdout)
                for vuln in parsed:
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity=vuln.get("severity", "high"),
                        title=vuln["title"],
                        description=vuln["description"],
                        poc=url,
                    )
                    vulnerable += 1
            except Exception:
                continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}
