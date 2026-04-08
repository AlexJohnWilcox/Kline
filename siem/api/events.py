from datetime import datetime

from fastapi import APIRouter, Query

from siem.models.event import Event
from siem.storage.es_client import get_es_client
from siem.storage.queries import search_events

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.get("")
async def list_events(
    source: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    q: str | None = None,
    time_from: datetime | None = Query(None, alias="from"),
    time_to: datetime | None = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> dict:
    es = await get_es_client()
    events, total = await search_events(
        es,
        source=source,
        category=category,
        severity=severity,
        host=host,
        query_text=q,
        time_from=time_from,
        time_to=time_to,
        page=page,
        size=size,
    )
    return {
        "total": total,
        "page": page,
        "size": size,
        "events": [e.model_dump() for e in events],
    }


@router.get("/{event_id}")
async def get_event(event_id: str) -> dict:
    es = await get_es_client()
    result = await es.search(
        index="siem-events-*",
        body={"query": {"term": {"id": event_id}}},
        size=1,
    )
    hits = result["hits"]["hits"]
    if not hits:
        return {"error": "Event not found"}
    event = Event.from_es_hit(hits[0])
    return event.model_dump()
