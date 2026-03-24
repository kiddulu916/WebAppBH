# workers/chain_worker/tools/chain_reporter.py
from __future__ import annotations

from datetime import datetime
from typing import Any

from lib_webbh import setup_logger
from lib_webbh.messaging import push_task

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainResult, TargetFindings
from workers.chain_worker.registry import get_registry

logger = setup_logger("chain_reporter")


class ChainReporter(ChainTestTool):
    name = "chain_reporter"
    weight_class = WeightClass.LIGHT

    def _build_description(self, result: ChainResult) -> str:
        lines = [f"Multi-stage attack chain: {result.chain_name}", ""]
        for i, step in enumerate(result.steps, 1):
            lines.append(f"Step {i}: [{step.action}] Target: {step.target} -> Result: {step.result}")
        if result.poc:
            lines.extend(["", f"PoC: {result.poc}"])
        return "\n".join(lines)

    def _build_tech_stack(self, result: ChainResult, category: str) -> dict[str, Any]:
        steps_json = []
        for step in result.steps:
            entry: dict[str, Any] = {"action": step.action, "target": step.target, "result": step.result}
            if step.screenshot_path:
                entry["screenshot"] = step.screenshot_path
            steps_json.append(entry)
        return {
            "chain_type": result.chain_name,
            "chain_category": category,
            "steps": steps_json,
            "total_steps": len(result.steps),
            "executed_at": datetime.utcnow().isoformat(),
        }

    async def report(self, results: list[ChainResult], target_id: int, findings: TargetFindings) -> dict[str, int]:
        registry = get_registry()
        reported = 0
        for result in results:
            if not result.success:
                continue
            chain = registry.get(result.chain_name)
            if chain is None:
                continue
            primary_asset_id = findings.assets[0].id if findings.assets else None
            title = f"CHAINED: {result.chain_name.replace('_', ' ').title()}"
            vuln_id = await self._save_vulnerability(
                target_id=target_id, asset_id=primary_asset_id,
                severity=chain.severity_on_success, title=title,
                description=self._build_description(result), poc=result.poc,
                source_tool=f"chain:{result.chain_name}",
            )
            if primary_asset_id:
                tech_stack = self._build_tech_stack(result, chain.category)
                await self._save_observation(primary_asset_id, tech_stack)
            await push_task(f"events:{target_id}", {
                "event": "CHAIN_SUCCESS", "chain": result.chain_name,
                "severity": chain.severity_on_success, "steps": len(result.steps),
                "target_id": target_id, "vulnerability_id": vuln_id,
            })
            reported += 1
        return {"reported": reported}

    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        results: list[ChainResult] = kwargs.get("_chain_results", [])
        findings: TargetFindings = kwargs["_findings"]
        return await self.report(results=results, target_id=target_id, findings=findings)
