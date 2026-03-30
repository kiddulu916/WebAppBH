# orchestrator/routes/resources.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/v1/resources", tags=["resources"])

# Resource guard instance injected at app startup
_guard = None


def set_guard(guard):
    global _guard
    _guard = guard


class OverrideRequest(BaseModel):
    tier: Optional[str] = None


@router.get("/status")
async def get_status():
    tier = await _guard.get_current_tier()
    return {"tier": tier, "thresholds": _guard.THRESHOLDS}


@router.post("/override")
async def override_tier(body: OverrideRequest):
    if body.tier:
        _guard.set_override(body.tier)
    else:
        _guard.clear_override()
    return {"override": body.tier}