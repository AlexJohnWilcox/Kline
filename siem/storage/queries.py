from datetime import UTC, datetime, timedelta
from typing import Any

from elasticsearch import AsyncElasticsearch

from siem.models.event import Event
from siem.storage.indices import get_event_index


async def search_events(
    es: AsyncElasticsearch,
    *,
    source: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    query_text: str | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    page: int = 1,
    size: int = 50,
) -> tuple[list[Event], int]:
    """Search events with filters. Returns (events, total_count)."""
    must: list[dict[str, Any]] = []

    if source:
        must.append({"term": {"source": source}})
    if category:
        must.append({"term": {"category": category}})
    if severity:
        must.append({"term": {"severity": severity}})
    if host:
        must.append({"term": {"host": host}})
    if query_text:
        must.append({"match": {"message": query_text}})

    time_range: dict[str, str] = {}
    if time_from:
        time_range["gte"] = time_from.isoformat()
    if time_to:
        time_range["lte"] = time_to.isoformat()
    if time_range:
        must.append({"range": {"timestamp": time_range}})

    body: dict[str, Any] = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "from": (page - 1) * size,
        "size": size,
    }

    result = await es.search(index="siem-events-*", body=body)
    total = result["hits"]["total"]["value"]
    events = [Event.from_es_hit(hit) for hit in result["hits"]["hits"]]
    return events, total


async def index_event(es: AsyncElasticsearch, event: Event) -> None:
    """Index a single event."""
    await es.index(
        index=get_event_index(),
        id=event.id,
        document=event.to_es_doc(),
    )


async def index_events_bulk(es: AsyncElasticsearch, events: list[Event]) -> int:
    """Bulk index events. Returns number indexed."""
    if not events:
        return 0

    operations: list[dict[str, Any]] = []
    for event in events:
        # Route on the event's own timestamp, not on now(). Event indices
        # are daily so that retention can express "30 days"; computing one
        # index for the whole batch at ingest time breaks that for anything
        # not happening right now. A 30-day cold-start backfill would land
        # ~1.5M rows spanning a month in a single siem-events-<today>, which
        # retention then holds for 30 days from ingest -- up to ~60 days of
        # event age in one index, which is the exact thing daily indices
        # were introduced to stop.
        operations.append(
            {"index": {"_index": get_event_index(event.timestamp), "_id": event.id}}
        )
        operations.append(event.to_es_doc())

    result = await es.bulk(operations=operations)
    if not result.get("errors"):
        return len(events)
    failed = sum(
        1 for item in result.get("items", [])
        if next(iter(item.values())).get("error") is not None
    )
    return len(events) - failed


async def get_event_stats(
    es: AsyncElasticsearch,
    hours: int = 24,
) -> dict[str, Any]:
    """Get event statistics for the dashboard."""
    time_from = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()

    body = {
        "query": {"range": {"timestamp": {"gte": time_from}}},
        "size": 0,
        "aggs": {
            "by_source": {"terms": {"field": "source", "size": 20}},
            "by_severity": {"terms": {"field": "severity", "size": 10}},
            "by_category": {"terms": {"field": "category", "size": 10}},
            "by_host": {"terms": {"field": "host", "size": 10}},
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "1h",
                }
            },
        },
    }

    result = await es.search(index="siem-events-*", body=body)
    return {
        "total": result["hits"]["total"]["value"],
        "by_source": result["aggregations"]["by_source"]["buckets"],
        "by_severity": result["aggregations"]["by_severity"]["buckets"],
        "by_category": result["aggregations"]["by_category"]["buckets"],
        "by_host": result["aggregations"]["by_host"]["buckets"],
        "timeline": result["aggregations"]["timeline"]["buckets"],
    }
