from fastapi import APIRouter, Query

from siem.storage.es_client import get_es_client
from siem.storage.queries import get_event_stats

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/stats")
async def dashboard_stats(hours: int = Query(24, ge=1, le=168)) -> dict:
    es = await get_es_client()
    return await get_event_stats(es, hours=hours)


@router.get("/timeline")
async def dashboard_timeline(hours: int = Query(24, ge=1, le=168)) -> dict:
    es = await get_es_client()
    stats = await get_event_stats(es, hours=hours)
    return {
        "hours": hours,
        "buckets": stats["timeline"],
    }
