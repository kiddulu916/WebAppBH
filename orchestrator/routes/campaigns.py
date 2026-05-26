# orchestrator/routes/campaigns.py
import json
import os
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel
from lib_webbh.database import get_session, Campaign, Target
from lib_webbh import setup_logger

logger = setup_logger("campaigns-route")
router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])


class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[dict]
    scope_config: dict | None = None
    tester_credentials: dict | None = None
    testing_user: dict | None = None
    rate_limit: int = 50


def _write_credentials(
    target_id: int,
    tester: dict | None,
    testing_user: dict | None,
    base_dir: str = "shared/config",
) -> None:
    if not tester and not testing_user:
        return
    config_dir = Path(base_dir) / str(target_id)
    config_dir.mkdir(parents=True, exist_ok=True)
    creds_path = config_dir / "credentials.json"
    creds_path.write_text(json.dumps({"tester": tester, "testing_user": testing_user}))
    os.chmod(creds_path, 0o600)


@router.post("", status_code=201)
async def create_campaign(body: CampaignCreate):
    async with get_session() as session:
        try:
            campaign = Campaign(
                name=body.name,
                description=body.description,
                scope_config=body.scope_config,
                rate_limit=body.rate_limit,
                has_credentials=body.tester_credentials is not None,
            )
            session.add(campaign)
            await session.flush()

            for t in body.targets:
                target = Target(
                    company_name=t.get("company_name", body.name),
                    base_domain=t["domain"],
                    campaign_id=campaign.id,
                    target_type="seed",
                    priority=100,
                )
                session.add(target)

            await session.commit()
            await session.refresh(campaign)

            # Write credentials for each target after commit so IDs are assigned
            from sqlalchemy import select
            result = await session.execute(
                select(Target).where(Target.campaign_id == campaign.id)
            )
            for tgt in result.scalars().all():
                try:
                    _write_credentials(tgt.id, body.tester_credentials, body.testing_user)
                except Exception as exc:
                    logger.warning(
                        "Failed to write credentials for target",
                        extra={"target_id": tgt.id, "error": str(exc)},
                    )

        except Exception:
            await session.rollback()
            raise

        return {"id": campaign.id, "name": campaign.name, "status": campaign.status}


@router.get("")
async def list_campaigns():
    from sqlalchemy import select
    async with get_session() as session:
        result = await session.execute(select(Campaign))
        campaigns = result.scalars().all()
        return [{"id": c.id, "name": c.name, "status": c.status} for c in campaigns]
