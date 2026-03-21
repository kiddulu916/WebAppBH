"""Reporting pipeline: 4 sequential stages with checkpointing."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState
from lib_webbh.messaging import push_task

from workers.reporting_worker.data_gatherer import gather_report_data
from workers.reporting_worker.deduplicator import deduplicate_and_enrich
from workers.reporting_worker.renderers.executive_renderer import ExecutiveRenderer
from workers.reporting_worker.renderers.markdown_renderer import MarkdownRenderer
from workers.reporting_worker.renderers.technical_renderer import TechnicalRenderer

logger = setup_logger("reporting_pipeline")


@dataclass
class Stage:
    name: str


STAGES: list[Stage] = [
    Stage("data_gathering"),
    Stage("deduplication"),
    Stage("rendering"),
    Stage("export"),
]

STAGE_INDEX: dict[str, int] = {s.name: i for i, s in enumerate(STAGES)}

FORMAT_RENDERERS = {
    "hackerone_md": MarkdownRenderer,
    "bugcrowd_md": MarkdownRenderer,
    "executive_pdf": ExecutiveRenderer,
    "technical_pdf": TechnicalRenderer,
}


class Pipeline:
    async def run(
        self,
        target_id: int,
        formats: list[str],
        platform: str,
        container_name: str,
        output_base: str = "/app/shared/reports",
    ) -> list[str]:
        log = logger.bind(target_id=target_id)
        start_index = await self._get_resume_index(target_id, container_name)
        all_output_paths: list[str] = []

        # Stage 1: Data Gathering
        if start_index <= 0:
            log.info("Starting stage", extra={"stage": "data_gathering"})
            ctx = await gather_report_data(target_id)
            await self._update_phase(target_id, container_name, "data_gathering")
            await push_task(f"events:{target_id}", {"event": "stage_complete", "stage": "data_gathering"})
        else:
            ctx = await gather_report_data(target_id)

        # Stage 2: Deduplication
        if start_index <= 1:
            log.info("Starting stage", extra={"stage": "deduplication"})
            report_data = deduplicate_and_enrich(ctx, platform=platform, formats=formats)
            await self._update_phase(target_id, container_name, "deduplication")
            await push_task(f"events:{target_id}", {"event": "stage_complete", "stage": "deduplication"})
        else:
            report_data = deduplicate_and_enrich(ctx, platform=platform, formats=formats)

        # Stage 3: Rendering
        if start_index <= 2:
            log.info("Starting stage", extra={"stage": "rendering"})
            render_dir = os.path.join(output_base, str(target_id), "_render")
            os.makedirs(render_dir, exist_ok=True)

            for fmt in formats:
                renderer_cls = FORMAT_RENDERERS.get(fmt)
                if renderer_cls is None:
                    log.warning("Unknown format, skipping", extra={"format": fmt})
                    continue
                renderer = renderer_cls()
                if fmt == "bugcrowd_md":
                    report_data.platform = "bugcrowd"
                paths = renderer.render(report_data, output_dir=render_dir)
                all_output_paths.extend(paths)
                await push_task(f"events:{target_id}", {"event": "report_format_complete", "format": fmt})
                log.info("Format rendered", extra={"format": fmt, "paths": paths})

            await self._update_phase(target_id, container_name, "rendering")

        # Stage 4: Export
        if start_index <= 3:
            log.info("Starting stage", extra={"stage": "export"})
            export_dir = os.path.join(output_base, str(target_id))
            final_paths: list[str] = []
            for src in all_output_paths:
                dst = os.path.join(export_dir, os.path.basename(src))
                if os.path.abspath(src) != os.path.abspath(dst):
                    shutil.move(src, dst)
                final_paths.append(dst)

            # Clean up temp render dir
            render_dir = os.path.join(export_dir, "_render")
            if os.path.isdir(render_dir):
                shutil.rmtree(render_dir, ignore_errors=True)

            all_output_paths = final_paths
            await self._update_phase(target_id, container_name, "export")
            await self._mark_completed(target_id, container_name)
            await push_task(f"events:{target_id}", {
                "event": "report_complete", "formats": formats,
            })

        return all_output_paths

    async def _get_resume_index(self, target_id: int, container_name: str) -> int:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row and row.current_phase and row.status != "COMPLETED":
                idx = STAGE_INDEX.get(row.current_phase, -1)
                return idx + 1
        return 0

    async def _update_phase(self, target_id: int, container_name: str, phase: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.current_phase = phase
                row.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _mark_completed(self, target_id: int, container_name: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.status = "COMPLETED"
                row.last_seen = datetime.now(timezone.utc)
                await session.commit()
