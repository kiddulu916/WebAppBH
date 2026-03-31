# workers/cryptography/base_tool.py
from abc import ABC, abstractmethod
from lib_webbh import get_session, Vulnerability


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