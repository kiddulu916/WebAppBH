# workers/cryptography/tools/algorithm_auditor.py
"""Algorithm auditor — detects weak cryptographic algorithms."""

import aiohttp
import asyncio
from workers.cryptography.base_tool import CryptographyTool


class AlgorithmAuditor(CryptographyTool):
    """Audit for weak or deprecated cryptographic algorithms."""

    async def execute(self, target_id: int, **kwargs):
        """Execute algorithm auditing against target."""
        domains = await self._get_target_domains(target_id)

        for domain in domains:
            await self._audit_domain_algorithms(target_id, domain)

    async def _get_target_domains(self, target_id: int):
        """Get domains for the target."""
        from lib_webbh import get_session, Target
        from sqlalchemy import select

        async with get_session() as session:
            result = await session.execute(
                select(Target.base_domain).where(Target.id == target_id)
            )
            row = result.fetchone()
            if row:
                return [row[0]]
        return []

    async def _audit_domain_algorithms(self, target_id: int, domain: str):
        """Audit cryptographic algorithms for a domain."""
        # Use sslyze if available for detailed algorithm analysis
        try:
            cmd = ["sslyze", domain]
            output = await self.run_subprocess(cmd, timeout=60)
            await self._analyze_sslyze_output(target_id, domain, output)
        except Exception:
            # Fallback to basic checks
            await self._basic_algorithm_checks(target_id, domain)

    async def _analyze_sslyze_output(self, target_id: int, domain: str, output: str):
        """Analyze sslyze output for weak algorithms."""
        weak_indicators = [
            "RC4",
            "MD5",
            "SHA1",
            "DES",
            "3DES",
            "NULL",
            "EXPORT",
        ]

        found_weak = []
        output_lower = output.lower()

        for indicator in weak_indicators:
            if indicator.lower() in output_lower:
                found_weak.append(indicator)

        if found_weak:
            await self.save_vulnerability(
                target_id=target_id,
                severity="high",
                title="Weak Cryptographic Algorithms",
                description=f"Domain {domain} supports weak cryptographic algorithms: {', '.join(found_weak)}",
                poc=f"https://{domain}",
                evidence=output[:500],
                vuln_type="weak_crypto",
            )

    async def _basic_algorithm_checks(self, target_id: int, domain: str):
        """Perform basic algorithm checks."""
        # Check for common weak algorithm indicators in HTTP headers
        async with aiohttp.ClientSession() as session:
            try:
                url = f"https://{domain}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    # Check security headers
                    headers = resp.headers

                    # Check for weak HSTS settings
                    hsts = headers.get("Strict-Transport-Security", "")
                    if hsts and "max-age=0" in hsts:
                        await self.save_vulnerability(
                            target_id=target_id,
                            severity="medium",
                            title="Weak HSTS Configuration",
                            description=f"Domain {domain} has HSTS with max-age=0",
                            poc=url,
                            vuln_type="weak_crypto",
                        )

                    # Check for missing security headers
                    security_headers = [
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                    ]

                    missing_headers = [h for h in security_headers if h not in headers]
                    if missing_headers:
                        await self.save_vulnerability(
                            target_id=target_id,
                            severity="low",
                            title="Missing Security Headers",
                            description=f"Domain {domain} is missing security headers: {', '.join(missing_headers)}",
                            poc=url,
                            vuln_type="weak_crypto",
                        )

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                # Log the error but continue auditing other domains
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to audit algorithms for {domain}: {str(e)}")