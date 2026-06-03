# workers/cryptography/base_tool.py
from abc import ABC, abstractmethod
import asyncio
import os
from lib_webbh import get_session, Vulnerability
from lib_webbh.database import Asset

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))


class CryptographyTool(ABC):
    """Abstract base for all cryptography tools."""

    worker_type = "cryptography"

    @abstractmethod
    async def execute(self, target_id: int, **kwargs):
        """Run this tool against the target. Must be implemented by subclasses."""
        ...

    async def save_asset(self, target_id: int, asset_type: str, asset_value: str) -> int:
        """Insert or retrieve an Asset row; returns the asset id."""
        from sqlalchemy import select
        from sqlalchemy.exc import IntegrityError
        async with get_session() as session:
            existing = (await session.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == asset_type,
                    Asset.asset_value == asset_value,
                )
            )).scalar_one_or_none()
            if existing:
                return existing.id
            asset = Asset(
                target_id=target_id,
                asset_type=asset_type,
                asset_value=asset_value,
                source_tool=self.worker_type,
                scope_classification="in-scope",
            )
            session.add(asset)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = (await session.execute(
                    select(Asset).where(
                        Asset.target_id == target_id,
                        Asset.asset_type == asset_type,
                        Asset.asset_value == asset_value,
                    )
                )).scalar_one()
                return existing.id
            return asset.id

    async def save_vulnerability(self, target_id, **kwargs):
        """Helper: insert a Vulnerability record."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                worker_type=self.worker_type,
                **kwargs,
            )
            session.add(vuln)
            await session.commit()
            return vuln.id

    async def run_subprocess(self, cmd: list[str], timeout: int = TOOL_TIMEOUT) -> str:
        """Run a command and return decoded stdout."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise
        return stdout_bytes.decode()