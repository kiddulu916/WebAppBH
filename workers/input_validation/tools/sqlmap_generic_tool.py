"""Generic SQL injection testing using sqlmap."""

from __future__ import annotations

from lib_webbh.scope import ScopeManager
from workers.input_validation.base_tool import InputValidationTool
from workers.input_validation.concurrency import WeightClass


class SqlmapGenericTool(InputValidationTool):
    """Test for SQL injection vulnerabilities using sqlmap."""

    name = "sqlmap_generic"
    weight_class = WeightClass.HEAVY

    def build_command(self, url: str, param: str | None = None) -> list[str]:
        """Build sqlmap command for generic SQL injection testing."""
        cmd = ["sqlmap", "-u", url, "--batch", "--random-agent"]
        if param:
            cmd.extend(["-p", param])
        # Add generic techniques
        cmd.extend(["--technique=BETU", "--level=3", "--risk=3"])
        return cmd

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Execute sqlmap against target URLs."""
        found = 0
        vulnerable = 0

        # Get URLs to test
        urls = await self._get_all_url_assets(target_id)

        for asset_id, url in urls:
            try:
                cmd = self.build_command(url)
                output = await self.run_subprocess(cmd)

                # Check if sqlmap found vulnerabilities
                if "Parameter:" in output and ("Type:" in output or "Title:" in output):
                    # Parse sqlmap output to extract vuln details
                    vuln_title = "SQL Injection Vulnerability"
                    vuln_desc = f"SQL injection found at {url}"

                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="high",
                        title=vuln_title,
                        description=vuln_desc,
                        poc=url,
                    )
                    vulnerable += 1
            except Exception as e:
                # Sqlmap might fail or timeout
                continue
            found += 1

        return {"found": found, "vulnerable": vulnerable}


class SqlmapOracleTool(SqlmapGenericTool):
    """Sqlmap configured for Oracle-specific techniques."""

    name = "sqlmap_oracle"

    def build_command(self, url: str, param: str | None = None) -> list[str]:
        cmd = super().build_command(url, param)
        cmd.extend(["--dbms=Oracle", "--technique=BEUST"])
        return cmd


class SqlmapMssqlTool(SqlmapGenericTool):
    """Sqlmap configured for MSSQL-specific techniques."""

    name = "sqlmap_mssql"

    def build_command(self, url: str, param: str | None = None) -> list[str]:
        cmd = super().build_command(url, param)
        cmd.extend(["--dbms=MSSQL", "--technique=BEUST"])
        return cmd


class SqlmapPostgresTool(SqlmapGenericTool):
    """Sqlmap configured for PostgreSQL-specific techniques."""

    name = "sqlmap_postgres"

    def build_command(self, url: str, param: str | None = None) -> list[str]:
        cmd = super().build_command(url, param)
        cmd.extend(["--dbms=PostgreSQL", "--technique=BEUST"])
        return cmd