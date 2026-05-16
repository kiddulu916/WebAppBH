# workers/info_gathering/tools/form_mapper.py
"""FormMapper — discover HTML forms using stdlib html.parser; write Parameter rows."""

import aiohttp
from html.parser import HTMLParser
from urllib.parse import urljoin

from sqlalchemy import select

from lib_webbh import Asset, Parameter, get_session
from workers.info_gathering.base_tool import InfoGatheringTool, logger


class _FormParser(HTMLParser):
    """Stateful HTML parser that collects all forms and their named inputs."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "form":
            self._current = {
                "action": urljoin(self.base_url, attr.get("action") or self.base_url),
                "method": (attr.get("method") or "GET").upper(),
                "inputs": [],
                "hidden_fields": [],
            }
        elif tag in ("input", "textarea", "select") and self._current is not None:
            name = attr.get("name")
            if not name:
                return
            input_type = attr.get("type", "text").lower()
            self._current["inputs"].append({
                "name": name,
                "type": input_type,
                "value": attr.get("value"),
            })
            if input_type == "hidden":
                self._current["hidden_fields"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


class FormMapper(InfoGatheringTool):
    """Discover and map HTML forms; write Parameter rows for all named inputs."""

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        if not target:
            return {"found": 0}

        rate_limiter = kwargs.get("rate_limiter")

        async with get_session() as session:
            rows = (await session.execute(
                select(Asset.asset_value, Asset.id).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                )
            )).all()

        # Always include the base domain; never cap the list
        urls = [(f"https://{target.base_domain}", None)] + [
            (row[0], row[1]) for row in rows
        ]

        saved = 0
        for url, existing_asset_id in urls:
            try:
                await self.acquire_rate_limit(rate_limiter)
                html = await self._fetch_html(url)
                if not html:
                    continue
                parser = _FormParser(base_url=url)
                parser.feed(html)
                if not parser.forms:
                    continue

                page_asset_id = existing_asset_id or await self.save_asset(
                    target_id, "form", url, "form_mapper",
                )
                if page_asset_id is None:
                    async with get_session() as session:
                        row = (await session.execute(
                            select(Asset.id).where(
                                Asset.target_id == target_id,
                                Asset.asset_type == "form",
                                Asset.asset_value == url,
                            )
                        )).first()
                        page_asset_id = row[0] if row else None
                if page_asset_id is None:
                    continue

                for form in parser.forms:
                    await self.save_observation(
                        asset_id=page_asset_id,
                        tech_stack={
                            "_probe": "form_mapper",
                            "action": form["action"],
                            "method": form["method"],
                            "input_count": len(form["inputs"]),
                            "hidden_fields": form["hidden_fields"],
                        },
                    )
                    await self._write_parameters(page_asset_id, form)
                saved += 1
            except Exception as e:
                logger.warning(f"FormMapper failed on {url}: {e}")
                continue

        return {"found": saved}

    async def _fetch_html(self, url: str) -> str | None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except Exception as e:
            logger.warning(f"FormMapper fetch failed for {url}: {e}")
        return None

    async def _write_parameters(self, asset_id: int, form: dict) -> None:
        async with get_session() as session:
            for inp in form["inputs"]:
                name = inp.get("name")
                if not name:
                    continue
                existing = (await session.execute(
                    select(Parameter).where(
                        Parameter.asset_id == asset_id,
                        Parameter.param_name == name,
                    )
                )).scalar_one_or_none()
                if existing is not None:
                    continue
                session.add(Parameter(
                    asset_id=asset_id,
                    param_name=name,
                    param_value=inp.get("value"),
                    source_url=form["action"],
                ))
            await session.commit()
