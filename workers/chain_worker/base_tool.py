# workers/chain_worker/base_tool.py
from __future__ import annotations
import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import Alert, JobState, Observation, Vulnerability
from lib_webbh.messaging import push_task
from sqlalchemy import select
from workers.chain_worker.concurrency import WeightClass

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))
CHAIN_STEP_DELAY_MS = int(os.environ.get("CHAIN_STEP_DELAY_MS", "500"))

logger = setup_logger("chain_worker")


class ChainTestTool(ABC):
    name: str
    weight_class: WeightClass

    @abstractmethod
    async def execute(self, target: Any, scope_manager: Any,
                      target_id: int, container_name: str, **kwargs: Any) -> dict[str, Any]:
        pass

    async def run_subprocess(self, cmd: list[str], timeout: int = TOOL_TIMEOUT) -> str:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise
        return stdout.decode(errors="replace")

    async def check_cooldown(self, target_id: int, container_name: str) -> bool:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
                JobState.last_tool_executed == self.name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row and row.last_seen:
                elapsed = (datetime.utcnow() - row.last_seen).total_seconds()
                return elapsed < COOLDOWN_HOURS * 3600
        return False

    async def update_tool_state(self, target_id: int, container_name: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.last_tool_executed = self.name
                row.last_seen = datetime.utcnow()
                await session.commit()

    async def _save_vulnerability(self, target_id: int, asset_id: int | None, severity: str,
                                   title: str, description: str, poc: str | None = None,
                                   source_tool: str | None = None) -> int:
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id, asset_id=asset_id, severity=severity,
                title=title, description=description, poc=poc,
                source_tool=source_tool or f"chain:{self.name}",
            )
            session.add(vuln)
            await session.flush()
            vuln_id = vuln.id
            if severity in ("critical", "high"):
                alert = Alert(
                    target_id=target_id, vulnerability_id=vuln_id,
                    alert_type=severity, message=f"[CHAIN] {title}", is_read=False,
                )
                session.add(alert)
                await session.commit()
                await push_task(f"events:{target_id}", {
                    "event": "CRITICAL_ALERT", "alert_type": severity,
                    "title": title, "vulnerability_id": vuln_id,
                })
            else:
                await session.commit()
            return vuln_id

    async def _save_observation(self, asset_id: int, tech_stack: dict[str, Any]) -> int:
        async with get_session() as session:
            obs = Observation(asset_id=asset_id, tech_stack=tech_stack)
            session.add(obs)
            await session.commit()
            return obs.id

    async def _create_action_required_alert(self, target_id: int, message: str) -> int:
        async with get_session() as session:
            alert = Alert(
                target_id=target_id, alert_type="action_required",
                message=message, is_read=False,
            )
            session.add(alert)
            await session.commit()
            await push_task(f"events:{target_id}", {
                "event": "ACTION_REQUIRED", "message": message,
            })
            return alert.id


async def take_screenshot(browser: Any, url: str, output_path: str) -> str | None:
    if browser is None:
        return None
    try:
        page = await browser.new_page()
        await page.goto(url, wait_until="networkidle", timeout=15000)
        await page.screenshot(path=output_path, full_page=True)
        await page.close()
        return output_path
    except Exception:
        return None


async def render_terminal_screenshot(text: str, output_path: str) -> str | None:
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            html = (
                f"<html><body style='background:#1e1e1e;color:#d4d4d4;"
                f"font-family:monospace;padding:20px;white-space:pre-wrap;'>"
                f"{text}</body></html>"
            )
            await page.set_content(html)
            await page.screenshot(path=output_path)
            await browser.close()
            return output_path
    except Exception:
        return None


async def step_delay() -> None:
    delay_ms = int(os.environ.get("CHAIN_STEP_DELAY_MS", "500"))
    await asyncio.sleep(delay_ms / 1000)
