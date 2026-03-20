from __future__ import annotations

import json
import os
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import Asset, Location, Observation, Parameter, Vulnerability
from sqlalchemy import select

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import AccountCreds, TargetFindings, TestAccounts

logger = setup_logger("findings_collector")


def _load_test_accounts(profile_path: str) -> TestAccounts | None:
    try:
        with open(profile_path) as f:
            profile = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    accounts = profile.get("test_accounts")
    if not accounts:
        return None
    try:
        return TestAccounts(
            attacker=AccountCreds(
                username=accounts["attacker"]["username"],
                password=accounts["attacker"]["password"],
            ),
            victim=AccountCreds(
                username=accounts["victim"]["username"],
                password=accounts["victim"]["password"],
            ),
        )
    except (KeyError, TypeError):
        return None


class FindingsCollector(ChainTestTool):
    name = "findings_collector"
    weight_class = WeightClass.LIGHT

    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        log = logger.bind(target_id=target_id)
        async with get_session() as session:
            vulns = list((await session.execute(
                select(Vulnerability).where(Vulnerability.target_id == target_id)
            )).scalars().all())
            assets = list((await session.execute(
                select(Asset).where(Asset.target_id == target_id)
            )).scalars().all())
            asset_ids = [a.id for a in assets]
            if asset_ids:
                params = list((await session.execute(
                    select(Parameter).where(Parameter.asset_id.in_(asset_ids))
                )).scalars().all())
                observations = list((await session.execute(
                    select(Observation).where(Observation.asset_id.in_(asset_ids))
                )).scalars().all())
                locations = list((await session.execute(
                    select(Location).where(Location.asset_id.in_(asset_ids))
                )).scalars().all())
            else:
                params, observations, locations = [], [], []

        profile_path = os.path.join("shared", "config", str(target_id), "profile.json")
        test_accounts = _load_test_accounts(profile_path)

        findings = TargetFindings(
            target_id=target_id, vulnerabilities=vulns, assets=assets,
            parameters=params, observations=observations, locations=locations,
            test_accounts=test_accounts,
        )
        log.info("Findings collected", extra={
            "vulns": len(vulns), "assets": len(assets), "params": len(params),
            "observations": len(observations), "locations": len(locations),
            "has_test_accounts": test_accounts is not None,
        })
        kwargs["_findings"] = findings
        return {
            "vulns": len(vulns), "assets": len(assets), "params": len(params),
            "observations": len(observations), "locations": len(locations),
        }
