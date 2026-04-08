from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Query

from siem.models.alert import Alert
from siem.storage.es_client import get_es_client

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    hours: int = Query(168, ge=1, le=720),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> dict:
    es = await get_es_client()

    must: list[dict[str, Any]] = []
    time_from = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
    must.append({"range": {"timestamp": {"gte": time_from}}})

    if status:
        must.append({"term": {"status": status}})
    if severity:
        must.append({"term": {"severity": severity}})
    if rule_id:
        must.append({"term": {"rule_id": rule_id}})

    body = {
        "query": {"bool": {"must": must}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "from": (page - 1) * size,
        "size": size,
    }

    try:
        result = await es.search(index="siem-alerts-*", body=body)
        total = result["hits"]["total"]["value"]
        alerts = [Alert.from_es_hit(hit).model_dump() for hit in result["hits"]["hits"]]
    except Exception:
        # Index may not exist yet
        total = 0
        alerts = []

    # Also get status counts for the tabs
    counts_body = {
        "query": {"range": {"timestamp": {"gte": time_from}}},
        "size": 0,
        "aggs": {
            "by_status": {"terms": {"field": "status", "size": 10}},
            "by_severity": {"terms": {"field": "severity", "size": 10}},
        },
    }

    status_counts = {"new": 0, "acknowledged": 0, "resolved": 0}
    try:
        counts_result = await es.search(index="siem-alerts-*", body=counts_body)
        for bucket in counts_result["aggregations"]["by_status"]["buckets"]:
            status_counts[bucket["key"]] = bucket["doc_count"]
    except Exception:
        pass

    return {
        "total": total,
        "page": page,
        "size": size,
        "alerts": alerts,
        "status_counts": status_counts,
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: str) -> dict:
    es = await get_es_client()
    result = await es.search(
        index="siem-alerts-*",
        body={"query": {"term": {"id": alert_id}}},
        size=1,
    )
    hits = result["hits"]["hits"]
    if not hits:
        return {"error": "Alert not found"}
    return Alert.from_es_hit(hits[0]).model_dump()


@router.patch("/{alert_id}")
async def update_alert_status(
    alert_id: str,
    new_status: Literal["acknowledged", "resolved"],
) -> dict:
    """Update an alert's status (acknowledge or resolve)."""
    es = await get_es_client()

    # Find the alert
    result = await es.search(
        index="siem-alerts-*",
        body={"query": {"term": {"id": alert_id}}},
        size=1,
    )
    hits = result["hits"]["hits"]
    if not hits:
        return {"error": "Alert not found"}

    hit = hits[0]
    index = hit["_index"]
    doc_id = hit["_id"]

    await es.update(
        index=index,
        id=doc_id,
        body={"doc": {"status": new_status}},
    )

    return {"status": "ok", "alert_id": alert_id, "new_status": new_status}
