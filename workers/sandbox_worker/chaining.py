"""Multi-mutation chaining: apply 2-3 mutations in sequence for WAF bypass."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from workers.sandbox_worker.mutator import mutate

if TYPE_CHECKING:
    from workers.sandbox_worker.context import InjectionContext

MAX_MUTATION_CHAIN_DEPTH = int(os.environ.get("MAX_MUTATION_CHAIN_DEPTH", "3"))
MAX_VARIANTS_PER_REQUEST = int(os.environ.get("MAX_VARIANTS_PER_REQUEST", "50"))


def chain_mutate(
    payload: str,
    vuln_type: str,
    depth: int = 2,
    max_variants: int = MAX_VARIANTS_PER_REQUEST,
    context: "InjectionContext | None" = None,
) -> list[str]:
    """Apply ``depth`` rounds of mutation, returning unique variants.

    Depth 1 is equivalent to a single ``mutate()`` call.
    Depth 2+ feeds each first-round variant back through ``mutate()``
    to produce compound transformations.

    Caps total output at ``max_variants`` to prevent combinatorial explosion.
    """
    depth = min(depth, MAX_MUTATION_CHAIN_DEPTH)

    current = mutate(payload, vuln_type, context=context)
    if depth <= 1:
        return current[:max_variants]

    seen: set[str] = {payload}
    seen.update(current)
    result: list[str] = list(current)

    for _round in range(depth - 1):
        next_gen: list[str] = []
        for variant in current:
            if len(result) >= max_variants:
                break
            for v2 in mutate(variant, vuln_type, context=context):
                if v2 not in seen:
                    seen.add(v2)
                    next_gen.append(v2)
                    result.append(v2)
                    if len(result) >= max_variants:
                        break
        current = next_gen
        if not current:
            break

    return result[:max_variants]
