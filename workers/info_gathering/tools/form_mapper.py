# workers/info_gathering/tools/form_mapper.py
"""FormMapper wrapper — discover and map HTML forms."""

import re
import aiohttp
from urllib.parse import urljoin

from workers.info_gathering.base_tool import InfoGatheringTool


class FormMapper(InfoGatheringTool):
    """Discover and map HTML forms from web pages."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        from lib_webbh.database import Asset
        from lib_webbh import get_session
        from sqlalchemy import select

        # Get URLs to scan for forms
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "url",
            )
            result = await session.execute(stmt)
            urls = [row[0] for row in result.all()]

        # Also scan the main domain
        urls.insert(0, f"https://{target.base_domain}")

        for url in urls[:20]:  # Limit to 20 pages
            try:
                forms = await self._extract_forms(url)
                if forms:
                    # Save the page as a form asset
                    asset_id = await self.save_asset(
                        target_id, "form", url, "form_mapper",
                    )
                    if asset_id:
                        await self.save_observation(
                            asset_id,
                            tech_stack={"forms": forms},
                            page_title=f"Form page: {url}",
                        )
            except Exception:
                continue

    async def _extract_forms(self, url: str) -> list[dict]:
        """Extract forms from a web page."""
        forms = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        form_pattern = r'<form[^>]*>(.*?)</form>'
                        form_matches = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)

                        for form_html in form_matches:
                            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html, re.IGNORECASE)

                            forms.append({
                                "action": urljoin(url, action.group(1)) if action else url,
                                "method": method.group(1).upper() if method else "GET",
                                "inputs": inputs,
                            })
        except Exception:
            pass
        return forms