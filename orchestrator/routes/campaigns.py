# orchestrator/routes/campaigns.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from lib_webbh.database import get_session, Campaign, Target

router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])


class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[dict]
    scope_config: dict | None = None
    tester_credentials: dict | None = None
    testing_user: dict | None = None
    rate_limit: int = 50


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