"""Markdown report renderer for HackerOne/Bugcrowd formats."""
from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from workers.reporting_worker.base_renderer import BaseRenderer
from workers.reporting_worker.models import ReportData

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

PLATFORM_TEMPLATES = {
    "hackerone": "hackerone.md.j2",
    "bugcrowd": "bugcrowd.md.j2",
}


class MarkdownRenderer(BaseRenderer):
    def render(self, data: ReportData, output_dir: str) -> list[str]:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=False)
        template_name = PLATFORM_TEMPLATES.get(data.platform, "hackerone.md.j2")
        template = env.get_template(template_name)

        rendered = template.render(
            company_name=data.company_name,
            base_domain=data.base_domain,
            generation_date=data.generation_date,
            summary_stats=data.summary_stats,
            finding_groups=data.finding_groups,
        )

        os.makedirs(output_dir, exist_ok=True)
        filename = f"{data.company_name}_{data.generation_date}_{data.platform}.md"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w") as f:
            f.write(rendered)

        return [filepath]
