from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel

from config.settings import settings
from siem.models.suppression import Suppression
from siem.storage.es_client import get_es_client

router = APIRouter(prefix="/api/v1/suppressions", tags=["suppressions"])

SUPPRESSION_INDEX = "siem-suppressions"


class CreateSuppressionRequest(BaseModel):
    rule_id: str
    reason: str
    match_fields: dict[str, str]
    source_alert_id: str
    ttl_hours: int | None = None  # None = permanent


@router.post("")
async def create_suppression(req: CreateSuppressionRequest) -> dict:
    expires_at = None
    ttl = req.ttl_hours if req.ttl_hours is not None else settings.default_suppression_ttl_hours
    if ttl > 0:
        expires_at = datetime.now(UTC) + timedelta(hours=ttl)

    suppression = Suppression(
        rule_id=req.rule_id,
        reason=req.reason,
        match_fields=req.match_fields,
        source_alert_id=req.source_alert_id,
        expires_at=expires_at,
    )

    es = await get_es_client()
    await es.index(
        index=SUPPRESSION_INDEX,
        id=suppression.id,
        document=suppression.to_es_doc(),
    )

    return suppression.to_es_doc()


@router.get("")
async def list_suppressions(
    status: str = Query("active"),
    rule_id: str | None = None,
) -> dict:
    es = await get_es_client()

    must: list[dict[str, Any]] = []
    if status:
        must.append({"term": {"status": status}})
    if rule_id:
        must.append({"term": {"rule_id": rule_id}})

    body: dict[str, Any] = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{"created_at": {"order": "desc"}}],
        "size": 100,
    }

    try:
        result = await es.search(index=SUPPRESSION_INDEX, body=body)
        suppressions = [
            Suppression.from_es_hit(hit).to_es_doc()
            for hit in result["hits"]["hits"]
        ]
        total = result["hits"]["total"]["value"]
    except Exception:
        suppressions = []
        total = 0

    return {"total": total, "suppressions": suppressions}


@router.delete("/{suppression_id}")
async def delete_suppression(suppression_id: str) -> dict:
    es = await get_es_client()

    result = await es.search(
        index=SUPPRESSION_INDEX,
        body={"query": {"term": {"id": suppression_id}}, "size": 1},
    )
    hits = result["hits"]["hits"]
    if not hits:
        return {"error": "Suppression not found"}

    hit = hits[0]
    await es.update(
        index=hit["_index"],
        id=hit["_id"],
        body={"doc": {"status": "deleted"}},
    )

    return {"status": "ok", "suppression_id": suppression_id}
