# workers/info_gathering/tools/execution_path_analyzer.py
"""Post-crawl execution path analyzer for Stage 7 (WSTG-INFO-07).

Consumes CrawlResult objects produced by Katana and Hakrawler, categorizes
all discovered URLs into execution path buckets, and writes a single summary
Observation to the database.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from lib_webbh import get_session, setup_logger
from lib_webbh.database import Observation
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("info-gathering-stage7")


@dataclass
class CrawlResult:
    """Structured output from a single crawler tool (Katana or Hakrawler)."""
    tool: str                          # "katana" | "hakrawler"
    urls: list[str] = field(default_factory=list)      # discovered non-WS URLs
    ws_urls: list[str] = field(default_factory=list)   # ws:// / wss:// URLs
    error: str | None = None           # set if tool failed; analyzer marks summary partial


# ---------------------------------------------------------------------------
# Categorization rules — priority order, first match wins
# ---------------------------------------------------------------------------
_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("websocket",     ("ws://", "wss://")),
    ("api_endpoint",  ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc")),
    ("auth_flow",     ("/login", "/logout", "/auth", "/oauth", "/signin", "/signup",
                       "/register", "/password", "/forgot", "/reset", "/sso", "/saml")),
    ("admin_panel",   ("/admin", "/administrator", "/management", "/manage",
                       "/control", "/cms", "/wp-admin", "/cpanel")),
    ("file_download", (".pdf", ".zip", ".csv", ".xlsx", ".docx", ".tar", ".gz")),
    ("static_asset",  (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ttf", ".ico")),
    ("error_page",    ("/error", "/404", "/500", "traceback", "exception")),
]

_DEPTH_MAP: dict[str, int] = {"low": 2, "medium": 3, "high": 5}


def _categorize(url: str) -> str:
    """Return the first matching category for a URL, or 'other'."""
    url_lower = url.lower()
    for category, patterns in _CATEGORIES:
        if any(p in url_lower for p in patterns):
            return category
    return "other"


class ExecutionPathAnalyzer(InfoGatheringTool):
    """Post-crawl in-process path analyzer for Stage 7.

    Invoked by pipeline.run() after asyncio.gather completes for the
    map_execution_paths stage. Not listed in stage.tools — it runs as a
    post-gather hook, mirroring FingerprintAggregator in Stage 2.
    """

    def __init__(self, asset_id: int, target_id: int):
        self.asset_id = asset_id
        self.target_id = target_id
        self.log = logger.bind(target_id=target_id, asset_id=asset_id)

    async def execute(self, target_id: int, **kwargs) -> None:
        # Invoked via write_summary(), not execute().
        pass

    async def write_summary(
        self, crawl_results: list[CrawlResult], intensity: str = "low",
    ) -> int | None:
        """Categorize all crawled URLs and write a single summary Observation.

        Returns the Observation.id, or None if no results were provided.
        """
        if not crawl_results:
            return None

        depth = _DEPTH_MAP.get(intensity, 2)
        all_urls: list[str] = []
        ws_seeds_used: list[str] = []
        tool_breakdown: dict[str, dict] = {}
        any_error = False

        for result in crawl_results:
            errored = result.error is not None
            if errored:
                any_error = True
            tool_breakdown[result.tool] = {
                "total": len(result.urls) + len(result.ws_urls),
                "errored": errored,
            }
            all_urls.extend(result.urls)
            all_urls.extend(result.ws_urls)
            ws_seeds_used.extend(result.ws_urls)

        # Build category map (all keys present even if empty)
        categories: dict[str, list[str]] = {cat: [] for cat, _ in _CATEGORIES}
        categories["other"] = []
        for url in all_urls:
            categories[_categorize(url)].append(url)

        tech_stack: dict = {
            "_probe": "execution_paths",
            "intensity": intensity,
            "depth": depth,
            "total_paths": len(all_urls),
            "ws_seeds_used": ws_seeds_used,
            "categories": categories,
            "tool_breakdown": tool_breakdown,
        }
        if any_error:
            tech_stack["partial"] = True

        async with get_session() as session:
            obs = Observation(
                asset_id=self.asset_id,
                tech_stack=tech_stack,
            )
            session.add(obs)
            await session.commit()
            await session.refresh(obs)
            self.log.info("Stage 7 summary observation written", extra={"obs_id": obs.id})
            return obs.id
