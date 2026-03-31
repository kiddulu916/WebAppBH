# workers/cryptography/base_tool.py
from abc import ABC, abstractmethod
import asyncio
import os
from lib_webbh import get_session, Vulnerability

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))


class CryptographyTool(ABC):
    """Abstract base for all cryptography tools."""

    worker_type = "cryptography"

    @abstractmethod
    async def execute(self, target_id: int, **kwargs):
        """Run this tool against the target. Must be implemented by subclasses."""
        ...

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