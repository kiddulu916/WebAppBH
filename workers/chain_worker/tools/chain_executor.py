# workers/chain_worker/tools/chain_executor.py
from __future__ import annotations

import os
from typing import Any

from lib_webbh import setup_logger

from workers.chain_worker.base_tool import ChainTestTool, step_delay
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainResult, EvaluationResult, TargetFindings
from workers.chain_worker.registry import ChainContext, get_registry

logger = setup_logger("chain_executor")


class ChainExecutor(ChainTestTool):
    name = "chain_executor"
    weight_class = WeightClass.HEAVY

    async def run_chains(
        self,
        viable_chains: list[tuple[str, EvaluationResult]],
        findings: TargetFindings,
        target_id: int,
        scope_manager: Any,
        evidence_dir: str,
        http_session: Any = None,
        zap_client: Any = None,
        msf_client: Any = None,
        browser: Any = None,
    ) -> list[ChainResult]:
        registry = get_registry()
        results: list[ChainResult] = []

        for chain_name, eval_result in viable_chains:
            chain = registry.get(chain_name)
            if chain is None:
                continue
            log = logger.bind(target_id=target_id, chain=chain_name)
            log.info("Executing chain")
            chain_evidence_dir = os.path.join(evidence_dir, chain_name)
            os.makedirs(chain_evidence_dir, exist_ok=True)

            context = ChainContext(
                target_id=target_id,
                findings=findings,
                matched_findings=eval_result.matched_findings,
                http_session=http_session,
                zap_client=zap_client,
                msf_client=msf_client,
                scope_manager=scope_manager,
                browser=browser,
                evidence_dir=chain_evidence_dir,
                log=log,
            )
            try:
                result = await chain.execute(context)
                results.append(result)
                log.info(
                    "Chain completed",
                    extra={"success": result.success, "steps": len(result.steps)},
                )
            except Exception as exc:
                log.error("Chain failed", extra={"error": str(exc)})
                results.append(
                    ChainResult(
                        success=False,
                        steps=[],
                        poc=None,
                        chain_name=chain_name,
                        failure_reason=str(exc),
                    )
                )
            await step_delay()
        return results

    async def execute(
        self,
        target: Any,
        scope_manager: Any,
        target_id: int,
        container_name: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        findings: TargetFindings = kwargs["_findings"]
        buckets = kwargs["_buckets"]
        viable = buckets.get("viable", [])
        evidence_dir = os.path.join(
            "shared", "config", str(target_id), "chain_evidence"
        )
        results = await self.run_chains(
            viable_chains=viable,
            findings=findings,
            target_id=target_id,
            scope_manager=scope_manager,
            evidence_dir=evidence_dir,
            http_session=kwargs.get("_http_session"),
            zap_client=kwargs.get("_zap_client"),
            msf_client=kwargs.get("_msf_client"),
            browser=kwargs.get("_browser"),
        )
        kwargs["_chain_results"] = results
        succeeded = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        return {
            "executed": len(results),
            "succeeded": len(succeeded),
            "failed": len(failed),
        }
