"""LLM-powered exploit chain discoverer (Task 5).

Proposes novel vulnerability chains via the local LLM and enforces
6 quality constraints before appending survivors to the viable bucket.

Constraints
-----------
1. Minimum finding confidence  (evidence_confidence >= 0.7)
2. Severity gate               (>= 1 medium-or-higher vuln)
3. Chain length limit           (2-4 steps)
4. Per-chain confidence score   (>= MIN_CHAIN_CONFIDENCE)
5. Distinctness check           (Jaccard < MAX_CHAIN_OVERLAP with templates)
6. Stated goal                  (non-empty goal string)
"""

from __future__ import annotations

import json
import os
from typing import Any

from lib_webbh import setup_logger
from lib_webbh.llm_client import LLMClient
from lib_webbh.prompts.chain_discovery import CHAIN_DISCOVERY_SYSTEM, build_chain_prompt

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass

logger = setup_logger("ai_chain_discoverer")

# Tunables
MAX_AI_CHAINS = int(os.environ.get("MAX_AI_CHAINS", "5"))
MIN_CHAIN_CONFIDENCE = float(os.environ.get("MIN_CHAIN_CONFIDENCE", "0.5"))
MIN_FINDING_CONFIDENCE = float(os.environ.get("MIN_FINDING_CONFIDENCE", "0.7"))
MAX_CHAIN_OVERLAP = float(os.environ.get("MAX_CHAIN_OVERLAP", "0.8"))

SEVERITY_GATE = {"critical", "high", "medium"}


# ---------------------------------------------------------------------------
# Constraint filter functions (pure, testable)
# ---------------------------------------------------------------------------

def filter_by_finding_confidence(
    chains: list[dict],
    confidence_map: dict[int, float],
    min_confidence: float = MIN_FINDING_CONFIDENCE,
) -> list[dict]:
    """Constraint 1: reject chains that reference any finding with confidence < threshold."""
    result = []
    for chain in chains:
        vuln_ids = chain.get("vuln_ids", [])
        if all(confidence_map.get(vid, 0.0) >= min_confidence for vid in vuln_ids):
            result.append(chain)
    return result


def filter_by_severity(
    chains: list[dict],
    severity_map: dict[int, str],
) -> list[dict]:
    """Constraint 2: at least one vuln in the chain must be medium-or-higher."""
    result = []
    for chain in chains:
        vuln_ids = chain.get("vuln_ids", [])
        if any(severity_map.get(vid, "info") in SEVERITY_GATE for vid in vuln_ids):
            result.append(chain)
    return result


def filter_by_length(chains: list[dict]) -> list[dict]:
    """Constraint 3: chain must have 2-4 steps."""
    return [c for c in chains if 2 <= len(c.get("steps", [])) <= 4]


def filter_by_chain_confidence(
    chains: list[dict],
    min_confidence: float = MIN_CHAIN_CONFIDENCE,
) -> list[dict]:
    """Constraint 4: drop chains below the confidence threshold."""
    return [c for c in chains if c.get("confidence", 0.0) >= min_confidence]


def _jaccard(a: set, b: set) -> float:
    """Jaccard similarity of two sets."""
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def filter_by_distinctness(
    chains: list[dict],
    template_vuln_id_sets: list[set[int]],
    max_overlap: float = MAX_CHAIN_OVERLAP,
) -> list[dict]:
    """Constraint 5: reject chains with >= max_overlap Jaccard similarity to any template."""
    result = []
    for chain in chains:
        chain_set = set(chain.get("vuln_ids", []))
        if any(_jaccard(chain_set, tpl) >= max_overlap for tpl in template_vuln_id_sets):
            continue
        result.append(chain)
    return result


def filter_by_goal(chains: list[dict]) -> list[dict]:
    """Constraint 6: chain must have a non-empty goal string."""
    return [c for c in chains if c.get("goal", "").strip()]


# ---------------------------------------------------------------------------
# AIChainDiscoverer tool
# ---------------------------------------------------------------------------

class AIChainDiscoverer(ChainTestTool):
    """LLM-powered chain hypothesis generator with 6-constraint pipeline."""

    name = "ai_chain_discoverer"
    weight_class = WeightClass.HEAVY

    def _prepare_findings(self, findings_data) -> tuple[list[dict], dict[int, float], dict[int, str]]:
        """Convert TargetFindings or raw list into the dicts needed for prompting + filtering."""
        raw_findings: list
        if hasattr(findings_data, "vulnerabilities"):
            raw_findings = []
            for v in findings_data.vulnerabilities:
                raw_findings.append({
                    "id": v.id,
                    "title": getattr(v, "title", ""),
                    "severity": getattr(v, "severity", "info"),
                    "cvss_score": getattr(v, "cvss_score", 0.0),
                    "evidence_confidence": getattr(v, "evidence_confidence", 0.5),
                    "description": getattr(v, "description", ""),
                    "source_tool": getattr(v, "source_tool", ""),
                })
        else:
            raw_findings = list(findings_data)

        confidence_map = {f["id"]: f.get("evidence_confidence", 0.0) for f in raw_findings}
        severity_map = {f["id"]: f.get("severity", "info") for f in raw_findings}
        return raw_findings, confidence_map, severity_map

    def _extract_template_vuln_ids(self, buckets: dict) -> list[set[int]]:
        """Pull vuln ID sets from template chain evaluation results."""
        result = []
        for _name, eval_result in buckets.get("viable", []):
            mf = getattr(eval_result, "matched_findings", {})
            if isinstance(mf, dict):
                ids = set()
                for v in mf.values():
                    if isinstance(v, int):
                        ids.add(v)
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, int):
                                ids.add(item)
                            elif hasattr(item, "id"):
                                ids.add(item.id)
                if ids:
                    result.append(ids)
        return result

    async def discover(
        self,
        findings_data,
        buckets: dict,
        llm_client: LLMClient | None = None,
    ) -> list[dict]:
        """Run LLM chain discovery and apply all 6 constraint filters.

        Returns the surviving chains (up to MAX_AI_CHAINS), sorted by
        confidence descending.
        """
        raw_findings, confidence_map, severity_map = self._prepare_findings(findings_data)

        # Pre-filter findings to those meeting confidence threshold (Constraint 1 prep)
        eligible = [f for f in raw_findings if f.get("evidence_confidence", 0) >= MIN_FINDING_CONFIDENCE]
        if not eligible:
            logger.info("No eligible findings for AI chain discovery (all below confidence threshold)")
            return []

        template_vuln_ids = self._extract_template_vuln_ids(buckets)
        existing_chains = buckets.get("viable", [])

        prompt = build_chain_prompt(eligible, existing_chains)

        client = llm_client or LLMClient()
        response = await client.generate(
            prompt=prompt,
            system=CHAIN_DISCOVERY_SYSTEM,
            json_mode=True,
            temperature=0.4,
            max_tokens=4096,
        )

        # Parse LLM response
        try:
            data = json.loads(response.text)
            chains = data.get("chains", [])
        except (json.JSONDecodeError, AttributeError):
            logger.warning("Failed to parse LLM chain discovery response")
            return []

        # Apply 6-constraint filter pipeline
        chains = filter_by_finding_confidence(chains, confidence_map)
        chains = filter_by_severity(chains, severity_map)
        chains = filter_by_length(chains)
        chains = filter_by_chain_confidence(chains)
        chains = filter_by_distinctness(chains, template_vuln_ids)
        chains = filter_by_goal(chains)

        # Sort by confidence desc, cap at MAX_AI_CHAINS
        chains.sort(key=lambda c: c.get("confidence", 0), reverse=True)
        chains = chains[:MAX_AI_CHAINS]

        logger.info("AI chain discovery complete", extra={"surviving_chains": len(chains)})
        return chains

    async def execute(
        self,
        target: Any,
        scope_manager: Any,
        target_id: int,
        container_name: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Pipeline integration: read _findings and _buckets, append AI chains to viable bucket."""
        findings = kwargs.get("_findings")
        buckets = kwargs.get("_buckets", {})

        if findings is None:
            logger.warning("No _findings in kwargs, skipping AI chain discovery")
            return {"ai_chains_added": 0}

        chains = await self.discover(findings, buckets)

        # Append surviving chains as synthetic viable entries
        for chain in chains:
            from workers.chain_worker.models import ChainViability, EvaluationResult
            eval_result = EvaluationResult(
                viability=ChainViability.VIABLE,
                matched_preconditions=[f"ai_chain_{chain.get('goal', 'unknown')[:30]}"],
                matched_findings={"vuln_ids": chain["vuln_ids"]},
            )
            buckets.setdefault("viable", []).append(
                (f"ai_chain_{chain['vuln_ids']}", eval_result)
            )

        return {"ai_chains_added": len(chains)}
