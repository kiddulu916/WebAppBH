# workers/info_gathering/tools/comment_harvester.py
"""CommentHarvester wrapper — extract comments from web pages."""

import re
import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class CommentHarvester(InfoGatheringTool):
    """Extract HTML/JS comments from web pages."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or not asset_id:
            return

        url = f"https://{target.base_domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        comments = self._extract_comments(html)
                        if comments:
                            await self.save_observation(
                                asset_id=asset_id,
                                tech_stack={"_source": "comment_harvester", "url": url, "comments": comments[:100]},
                            )
        except Exception as exc:
            logger.error("comment_harvester failed", url=url, error=str(exc))

    def _extract_comments(self, html: str) -> list[str]:
        """Extract HTML and JS comments."""
        html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        js_comments = re.findall(r'//.*?(?=\n|$)', html)
        js_block_comments = re.findall(r'/\*.*?\*/', html, re.DOTALL)

        all_comments = []
        for c in html_comments + js_comments + js_block_comments:
            cleaned = c.strip()
            if cleaned and len(cleaned) > 3:
                all_comments.append(cleaned[:500])
        return all_comments