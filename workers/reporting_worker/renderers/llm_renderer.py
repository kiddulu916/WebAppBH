"""LLM-powered report renderer for persuasive, platform-ready reports."""
from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from lib_webbh.llm_client import LLMClient
from lib_webbh.prompts.report_writer import SYSTEM_PROMPT, build_report_prompt

if TYPE_CHECKING:
    from workers.reporting_worker.models import ReportData


class LLMRenderer:
    """Generates reports by sending finding data to the local LLM."""

    def __init__(self, model: str | None = None):
        self._model = model

    async def render(self, data: "ReportData", output_dir: str) -> list[str]:
        client = LLMClient(model=self._model)
        prompt = build_report_prompt(data)

        response = await client.generate(
            prompt=prompt,
            system=SYSTEM_PROMPT,
            max_tokens=8192,
            temperature=0.3,
        )

        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", data.company_name)[:50]
        filename = f"{safe_name}_{data.generation_date}_{data.platform}_llm.md"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write(response.text)

        return [filepath]
