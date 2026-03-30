# workers/info_gathering/tools/metafile_parser.py
"""MetafileParser wrapper — parse robots.txt, sitemap.xml, and security.txt."""

import aiohttp
import re

from workers.info_gathering.base_tool import InfoGatheringTool


class MetafileParser(InfoGatheringTool):
    """Parse robots.txt, sitemap.xml, and security.txt for information."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        metafiles = [
            ("robots.txt", self._parse_robots),
            ("sitemap.xml", self._parse_sitemap),
            (".well-known/security.txt", self._parse_security_txt),
        ]

        for filename, parser in metafiles:
            try:
                url = f"https://{target.base_domain}/{filename}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            parsed = parser(content)
                            if parsed:
                                await self.save_observation(
                                    target_id, "metafile",
                                    {"file": filename, "data": parsed},
                                    "metafile_parser"
                                )
            except Exception:
                continue

    def _parse_robots(self, content: str) -> dict:
        """Parse robots.txt for disallowed paths and sitemaps."""
        disallow = re.findall(r'Disallow:\s*(.+)', content, re.IGNORECASE)
        sitemaps = re.findall(r'Sitemap:\s*(.+)', content, re.IGNORECASE)
        return {
            "disallow": [d.strip() for d in disallow if d.strip()],
            "sitemaps": [s.strip() for s in sitemaps if s.strip()],
        }

    def _parse_sitemap(self, content: str) -> dict:
        """Parse sitemap.xml for URLs."""
        urls = re.findall(r'<loc>(.*?)</loc>', content, re.IGNORECASE)
        return {"urls": [u.strip() for u in urls if u.strip()][:200]}

    def _parse_security_txt(self, content: str) -> dict:
        """Parse security.txt for contact and policy information."""
        contacts = re.findall(r'Contact:\s*(.+)', content, re.IGNORECASE)
        policies = re.findall(r'Policy:\s*(.+)', content, re.IGNORECASE)
        return {
            "contacts": [c.strip() for c in contacts if c.strip()],
            "policies": [p.strip() for p in policies if p.strip()],
        }