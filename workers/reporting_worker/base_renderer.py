"""Base class for report renderers."""
from __future__ import annotations

from abc import ABC, abstractmethod

from workers.reporting_worker.models import ReportData


class BaseRenderer(ABC):
    @abstractmethod
    def render(self, data: ReportData, output_dir: str) -> list[str]:
        """Render the report and return list of output file paths."""
