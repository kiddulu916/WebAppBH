"""Executive summary PDF renderer."""
from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from workers.reporting_worker.base_renderer import BaseRenderer
from workers.reporting_worker.models import ReportData

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class ExecutiveRenderer(BaseRenderer):
    def render_html(self, data: ReportData) -> str:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
        template = env.get_template("executive.html.j2")
        return template.render(
            company_name=data.company_name,
            base_domain=data.base_domain,
            generation_date=data.generation_date,
            summary_stats=data.summary_stats,
            finding_groups=data.finding_groups,
        )

    def render(self, data: ReportData, output_dir: str) -> list[str]:
        from weasyprint import HTML

        html_str = self.render_html(data)
        os.makedirs(output_dir, exist_ok=True)
        filename = f"{data.company_name}_{data.generation_date}_executive.pdf"
        filepath = os.path.join(output_dir, filename)
        css_path = str(_TEMPLATES_DIR / "executive.css")
        HTML(string=html_str, base_url=str(_TEMPLATES_DIR)).write_pdf(filepath, stylesheets=[css_path])
        return [filepath]
