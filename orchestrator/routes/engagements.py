"""Engagement lookup endpoints — search platforms and fetch program policies."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from lib_webbh import setup_logger
from lib_webbh.platform_api.engagement_fetcher import (
    fetch_engagement,
    search_programs,
)

logger = setup_logger("engagements-route")
router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])

SUPPORTED_PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack"}


class EngagementSearchRequest(BaseModel):
    platform: str
    company_name: str
    credentials: dict | None = None


class EngagementFetchRequest(BaseModel):
    platform: str
    handle: str
    url: str
    credentials: dict | None = None
    use_llm: bool = True


@router.post("/search")
async def search_engagement(body: EngagementSearchRequest):
    """Phase 1: find matching programs by company name.

    Returns:
    - {"type": "prefill", "data": CampaignFormPrefill} if exactly one match (auto-fetched)
    - {"type": "candidates", "data": [ProgramCandidate, ...]} if multiple matches
    """
    if body.platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unsupported platform: {body.platform!r}")

    try:
        candidates = await search_programs(
            platform=body.platform,
            company_name=body.company_name,
            credentials=body.credentials,
        )
    except Exception as exc:
        logger.warning("Engagement search failed", error=str(exc))
        raise HTTPException(status_code=502, detail=f"Platform search failed: {exc}") from exc

    if not candidates:
        raise HTTPException(
            status_code=404,
            detail=f"No program found for '{body.company_name}' on {body.platform} — try a different name",
        )

    if len(candidates) == 1:
        c = candidates[0]
        try:
            prefill = await fetch_engagement(
                platform=body.platform,
                handle=c.handle,
                url=c.url,
                credentials=body.credentials,
                use_llm=False,
            )
        except Exception as exc:
            logger.warning("Auto-fetch failed", error=str(exc))
            raise HTTPException(status_code=502, detail=f"Program fetch failed: {exc}") from exc
        return {"type": "prefill", "data": asdict(prefill)}

    return {"type": "candidates", "data": [asdict(c) for c in candidates]}


@router.post("/fetch")
async def fetch_engagement_endpoint(body: EngagementFetchRequest):
    """Phase 2: fetch full policy for a known program handle/URL."""
    if body.platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unsupported platform: {body.platform!r}")

    try:
        prefill = await fetch_engagement(
            platform=body.platform,
            handle=body.handle,
            url=body.url,
            credentials=body.credentials,
            use_llm=body.use_llm,
        )
    except Exception as exc:
        logger.warning("Engagement fetch failed", error=str(exc))
        raise HTTPException(status_code=502, detail=f"Program fetch failed: {exc}") from exc

    return asdict(prefill)
