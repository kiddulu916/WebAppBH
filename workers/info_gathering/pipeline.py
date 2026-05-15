# workers/info_gathering/pipeline.py
import asyncio
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from lib_webbh import Asset, get_session, push_task, setup_logger
from lib_webbh.deep_classifier import DeepClassifier
from lib_webbh.pipeline_checkpoint import CheckpointMixin
from lib_webbh.scope import ScopeManager


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Stage 2 (WSTG-INFO-02) probe imports — kept together so the STAGES entry below
# stays readable.
from .tools.amass_active import AmassActive
from .tools.amass_passive import AmassPassive
from .tools.app_path_enumerator import AppPathEnumerator
from .tools.application_mapper import ApplicationMapper
from .tools.archive_prober import ArchiveProber
from .tools.architecture_modeler import ArchitectureModeler
from .tools.assetfinder import Assetfinder
from .tools.attack_surface_analyzer import AttackSurfaceAnalyzer
from .tools.banner_probe import BannerProbe
from .tools.cache_prober import CacheProber
from .tools.censys_searcher import CensysSearcher
from .tools.comment_harvester import CommentHarvester
from .tools.cookie_fingerprinter import CookieFingerprinter
from .tools.ct_log_searcher import CTLogSearcher
from .tools.dork_engine import DorkEngine
from .tools.error_page_probe import ErrorPageProbe
from .tools.form_mapper import FormMapper
from .tools.hakrawler import Hakrawler
from .tools.header_order_probe import HeaderOrderProbe
from .tools.httpx import Httpx
from .tools.js_secret_scanner import JsSecretScanner
from .tools.katana import Katana
from .tools.liveness_probe import LivenessProbe
from .tools.massdns import Massdns
from .tools.metadata_extractor import MetadataExtractor
from .tools.meta_tag_analyzer import MetaTagAnalyzer
from .tools.metafile_parser import MetafileParser
from .tools.method_probe import MethodProbe
from .tools.naabu import Naabu
from .tools.paramspider import Paramspider
from .tools.redirect_body_inspector import RedirectBodyInspector
from .tools.securitytrails_searcher import SecurityTrailsSearcher
from .tools.shodan_searcher import ShodanSearcher
from .tools.source_map_prober import SourceMapProber
from .tools.subfinder import Subfinder
from .tools.tls_probe import TLSProbe
from .tools.vhost_prober import VHostProber
from .tools.waf_probe import WAFProbe
from .tools.wappalyzer import Wappalyzer
from .tools.waybackurls import Waybackurls
from .tools.webanalyze import Webanalyze
from .tools.whatweb import WhatWeb

from workers.info_gathering.fingerprint_aggregator import FingerprintAggregator, ProbeResult

STAGES = [
    Stage(name="search_engine_recon", section_id="4.1.1", tools=[DorkEngine, ArchiveProber, CacheProber, ShodanSearcher, CensysSearcher, SecurityTrailsSearcher]),
    Stage(name="web_server_fingerprint", section_id="4.1.2", tools=[
        LivenessProbe, BannerProbe, HeaderOrderProbe, MethodProbe,
        ErrorPageProbe, TLSProbe, WAFProbe, WhatWeb,
    ]),
    Stage(name="web_server_metafiles", section_id="4.1.3", tools=[MetafileParser, MetaTagAnalyzer]),
    Stage(name="enumerate_applications", section_id="4.1.4", tools=[
        Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns,
        VHostProber,
        Naabu,
        AppPathEnumerator,
        CTLogSearcher,
    ]),
    Stage(name="review_comments", section_id="4.1.5", tools=[
        CommentHarvester, MetadataExtractor,
        JsSecretScanner, SourceMapProber, RedirectBodyInspector,
    ]),
    Stage(name="identify_entry_points", section_id="4.1.6", tools=[FormMapper, Paramspider, Httpx]),
    Stage(name="map_execution_paths", section_id="4.1.7", tools=[Katana, Hakrawler]),
    Stage(name="review_comments_deep", section_id="4.1.5", tools=[
        CommentHarvester, MetadataExtractor,
        JsSecretScanner, SourceMapProber, RedirectBodyInspector,
    ]),
    Stage(name="fingerprint_framework", section_id="4.1.8", tools=[Wappalyzer, CookieFingerprinter, Webanalyze]),
    Stage(name="map_architecture", section_id="4.1.9", tools=[Waybackurls, ArchitectureModeler]),
    Stage(name="map_application", section_id="4.1.10", tools=[ApplicationMapper, AttackSurfaceAnalyzer]),
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}

# WSTG-INFO-02 section id — matched in run() to gate FingerprintAggregator invocation.
_STAGE2_SECTION = "4.1.2"

logger = setup_logger("info-gathering-pipeline")


class Pipeline(CheckpointMixin):
    """Orchestrates the 10-stage info gathering pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str):
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    def _filter_stages(self, playbook: dict | None) -> list[Stage]:
        """Return only the stages enabled by the playbook config."""
        from lib_webbh.playbooks import get_worker_stages
        worker_stages = get_worker_stages(playbook, "info_gathering")
        if worker_stages is None:
            return list(STAGES)
        if not worker_stages:
            return []
        enabled_names = {
            s["name"] for s in worker_stages if s.get("enabled", True)
        }
        return [stage for stage in STAGES if stage.name in enabled_names]

    def _select_host(self, target) -> str:
        """Pick the host this pipeline run will fingerprint.

        The seed run uses the target's base_domain. Child-asset runs (Stage 4
        spawns a new pipeline per discovered subdomain) override via ``host=``
        on ``run``.
        """
        return target.base_domain

    def _get_intensity(self, playbook: dict | None) -> str:
        """Read ``fingerprint_intensity`` from the playbook's Stage 2 config."""
        from lib_webbh.playbooks import get_worker_stages
        stages = get_worker_stages(playbook, "info_gathering") or []
        for s in stages:
            if s.get("name") == "web_server_fingerprint":
                config = s.get("config") or {}
                value = config.get("fingerprint_intensity", "low")
                if value in ("low", "medium", "high"):
                    return value
        return "low"

    async def _fetch_target(self):
        """Load the Target row for this pipeline's target_id."""
        from lib_webbh.database import Target
        async with get_session() as session:
            stmt = select(Target).where(Target.id == self.target_id)
            return (await session.execute(stmt)).scalar_one()

    async def _resolve_subject_asset(self, host: str) -> int:
        """Resolve (or create) the subject Asset for ``host`` under this target."""
        from workers.info_gathering.base_tool import InfoGatheringTool

        class _Helper(InfoGatheringTool):
            async def execute(self, target_id: int, **kwargs) -> None:
                ...

        helper = _Helper()
        target_obj = await self._fetch_target()
        return await helper.resolve_or_create_asset(
            self.target_id, host, base_domain=target_obj.base_domain,
        )

    def _stage2_raw_from_results(self, results: list) -> dict[str, Any]:
        """Build the ``raw`` dict consumed by FingerprintAggregator.emit_info_leaks."""
        raw: dict[str, Any] = {}
        for r in results:
            if not isinstance(r, ProbeResult) or r.error is not None:
                continue
            if r.probe == "banner":
                raw["banner"] = r.signals.get("_raw") or {}
            elif r.probe == "error_page":
                signature_match = None
                for slot in ("origin_server", "framework", "edge"):
                    for s in r.signals.get(slot, []):
                        if s.get("src") == "error_page_signature":
                            signature_match = f"{s['value'].lower()}-default-404"
                            break
                    if signature_match:
                        break
                # Map vendor-derived id back to the canonical signature id used
                # by DEFAULT_ERROR_LEAKERS. The probe records the real id in
                # the Observation; here we just keep the parts emit_info_leaks
                # needs.
                raw["error_page"] = {
                    "obs_id": r.obs_id,
                    "signature_match": signature_match,
                }
        return raw

    def _stats_from_results(self, results: list) -> dict[str, Any]:
        """Derive the legacy SSE-event stats shape from a stage's results list."""
        stats = {"found": 0, "vulnerable": 0}
        for r in results:
            if isinstance(r, ProbeResult) or not isinstance(r, dict):
                continue
            stats["found"] += int(r.get("found", 0) or 0)
            stats["vulnerable"] += int(r.get("vulnerable", 0) or 0)
        return stats

    async def run(
        self, target, scope_manager: ScopeManager, headers: dict | None = None,
        playbook: dict | None = None, rate_limiter=None, host: str | None = None,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        host = host or self._select_host(target)
        asset_id = await self._resolve_subject_asset(host)
        intensity = self._get_intensity(playbook)

        completed_phase = await self._get_resume_stage()
        start_index = 0
        if completed_phase and completed_phase in STAGE_INDEX:
            start_index = STAGE_INDEX[completed_phase] + 1
            self.log.info(
                f"Resuming from stage {start_index}",
                extra={"completed_phase": completed_phase},
            )

        stages = self._filter_stages(playbook)
        for stage in stages[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            results = await self._run_stage(
                stage, target, scope_manager=scope_manager,
                headers=headers, rate_limiter=rate_limiter,
                asset_id=asset_id, host=host, intensity=intensity,
            )

            stats = self._stats_from_results(results)
            if stage.section_id == _STAGE2_SECTION:
                agg = FingerprintAggregator(
                    asset_id=asset_id, target_id=self.target_id, intensity=intensity,
                )
                probe_results = [r for r in results if isinstance(r, ProbeResult)]
                summary_obs_id = await agg.write_summary(probe_results)
                fingerprint = {
                    slot: agg._score_slot(slot, probe_results)
                    for slot in ("origin_server", "framework", "edge", "waf")
                }
                raw = self._stage2_raw_from_results(probe_results)
                vuln_ids = await agg.emit_info_leaks(fingerprint, raw)
                stats["probes"] = len(probe_results)
                stats["summary_written"] = summary_obs_id is not None
                stats["vulns"] = len(vuln_ids)

            self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
            await push_task(f"events:{self.target_id}", {
                "event": "STAGE_COMPLETE",
                "stage": stage.name,
                "stats": stats,
            })
            await self._checkpoint_stage(stage.name)

        await self._mark_completed()

        await push_task(f"events:{self.target_id}", {
            "event": "PIPELINE_COMPLETE",
            "target_id": self.target_id,
        })

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        rate_limiter=None,
        asset_id: int | None = None,
        host: str | None = None,
        intensity: str = "low",
    ) -> list:
        """Run all tools in a stage concurrently, return raw per-tool results.

        Returns a list of per-tool returns. Stage 2 probes return ``ProbeResult``;
        legacy tools still return ``{"found": N, "vulnerable": M}``-style dicts.
        Exceptions are logged and filtered out.
        """
        tools = [cls() for cls in stage.tools]

        tasks = [
            tool.execute(
                target_id=self.target_id,
                scope_manager=scope_manager,
                headers=headers,
                container_name=self.container_name,
                rate_limiter=rate_limiter,
                target=target,
                asset_id=asset_id,
                host=host,
                intensity=intensity,
            )
            for tool in tools
        ]

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        results: list = []
        for r in raw_results:
            if isinstance(r, Exception):
                self.log.error(f"Tool failed in {stage.name}", extra={"error": str(r)})
                continue
            results.append(r)

        # Post-stage: deep-classify any pending assets discovered by legacy tools.
        await self._classify_pending_assets(scope_manager)

        return results

    async def _classify_pending_assets(self, scope_manager: ScopeManager) -> int:
        """Run deep classification on all assets with scope_classification='pending'."""
        if not scope_manager._in_scope_patterns:
            return 0

        classifier = DeepClassifier(
            in_scope_domains=[
                p for p in scope_manager._in_scope_patterns
                if not any(c.isdigit() for c in p.split(".")[0])
            ],
            in_scope_ips=[
                p for p in scope_manager._in_scope_patterns
                if any(c.isdigit() for c in p.split(".")[0])
            ],
        )

        classified_count = 0
        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == self.target_id,
                Asset.scope_classification == "pending",
            )
            result = await session.execute(stmt)
            pending_assets = result.scalars().all()

            sem = asyncio.Semaphore(5)

            async def _classify_one(asset: Asset):
                async with sem:
                    deep_result = await classifier.classify_deep(
                        asset.asset_value,
                        asset_type=asset.asset_type,
                    )
                    asset.scope_classification = deep_result.classification
                    if deep_result.association_method:
                        asset.association_method = deep_result.association_method

            tasks = [_classify_one(a) for a in pending_assets]
            await asyncio.gather(*tasks, return_exceptions=True)
            await session.commit()
            classified_count = len(pending_assets)

        if classified_count:
            self.log.info(
                f"Deep-classified {classified_count} pending assets",
                extra={"classified": classified_count},
            )
        return classified_count
