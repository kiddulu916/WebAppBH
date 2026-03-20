import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.registry import get_chains_by_category
import workers.chain_worker.chains.file_processing  # noqa: F401


def test_chain_count():
    chains = get_chains_by_category("file_processing")
    assert len(chains) == 19


def test_chain_attributes():
    for chain in get_chains_by_category("file_processing"):
        assert chain.name
        assert chain.category == "file_processing"
        assert chain.severity_on_success in ("critical", "high")


@pytest.mark.anyio
async def test_all_not_viable_with_empty_findings():
    from workers.chain_worker.models import TargetFindings, ChainViability
    empty = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    for chain in get_chains_by_category("file_processing"):
        result = await chain.evaluate(empty)
        assert result.viability in (ChainViability.NOT_VIABLE, ChainViability.PARTIAL)
