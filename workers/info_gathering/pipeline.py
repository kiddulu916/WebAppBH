# workers/info_gathering/pipeline.py
from dataclasses import dataclass, field


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.dork_engine import DorkEngine
from .tools.archive_prober import ArchiveProber
from .tools.nmap import Nmap
from .tools.whatweb import WhatWeb
from .tools.httpx import Httpx
from .tools.metafile_parser import MetafileParser
from .tools.subfinder import Subfinder
from .tools.assetfinder import Assetfinder
from .tools.amass_passive import AmassPassive
from .tools.amass_active import AmassActive
from .tools.massdns import Massdns
from .tools.vhost_prober import VHostProber
from .tools.comment_harvester import CommentHarvester
from .tools.metadata_extractor import MetadataExtractor
from .tools.form_mapper import FormMapper
from .tools.paramspider import Paramspider
from .tools.katana import Katana
from .tools.hakrawler import Hakrawler
from .tools.wappalyzer import Wappalyzer
from .tools.cookie_fingerprinter import CookieFingerprinter
from .tools.webanalyze import Webanalyze
from .tools.naabu import Naabu
from .tools.waybackurls import Waybackurls
from .tools.architecture_modeler import ArchitectureModeler
from .tools.application_mapper import ApplicationMapper
from .tools.attack_surface_analyzer import AttackSurfaceAnalyzer
from .tools.cache_prober import CacheProber
from .tools.shodan_searcher import ShodanSearcher
from .tools.censys_searcher import CensysSearcher
from .tools.securitytrails_searcher import SecurityTrailsSearcher

STAGES = [
    Stage(name="search_engine_recon", section_id="4.1.1", tools=[DorkEngine, ArchiveProber, CacheProber, ShodanSearcher, CensysSearcher, SecurityTrailsSearcher]),
    Stage(name="web_server_fingerprint", section_id="4.1.2", tools=[Nmap, WhatWeb, Httpx]),
    Stage(name="web_server_metafiles", section_id="4.1.3", tools=[MetafileParser]),
    Stage(name="enumerate_subdomains", section_id="4.1.4", tools=[Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns, VHostProber]),
    Stage(name="review_comments", section_id="4.1.5", tools=[CommentHarvester, MetadataExtractor]),
    Stage(name="identify_entry_points", section_id="4.1.6", tools=[FormMapper, Paramspider, Httpx]),
    Stage(name="map_execution_paths", section_id="4.1.7", tools=[Katana, Hakrawler]),
    Stage(name="fingerprint_framework", section_id="4.1.8", tools=[Wappalyzer, CookieFingerprinter, Webanalyze]),
    Stage(name="map_architecture", section_id="4.1.9", tools=[Naabu, Waybackurls, ArchitectureModeler]),
    Stage(name="map_application", section_id="4.1.10", tools=[ApplicationMapper, AttackSurfaceAnalyzer]),  # Post-processing stage
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


import asyncio


from sqlalchemy import select

from lib_webbh import Asset, push_task, setup_logger, get_session
from lib_webbh.deep_classifier import DeepClassifier
from lib_webbh.pipeline_checkpoint import CheckpointMixin
from lib_webbh.scope import ScopeManager

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

    async def run(
        self, target, scope_manager: ScopeManager, headers: dict | None = None,
        playbook: dict | None = None,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
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

            stats = await self._run_stage(stage, target, scope_manager, headers)

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
    ) -> dict:
        """Run all tools in a stage concurrently, return aggregated stats."""
        tools = [cls() for cls in stage.tools]

        tasks = [
            tool.execute(
                target_id=self.target_id,
                scope_manager=scope_manager,
                headers=headers,
                container_name=self.container_name,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {"found": 0, "vulnerable": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(f"Tool failed in {stage.name}", extra={"error": str(r)})
                continue
            aggregated["found"] += r.get("found", 0)
            aggregated["vulnerable"] += r.get("vulnerable", 0)

        # Post-stage: deep-classify any pending assets
        classified = await self._classify_pending_assets(scope_manager)
        if classified:
            aggregated["classified"] = classified

        return aggregated

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

            # Classify in batches of 5 concurrent
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
