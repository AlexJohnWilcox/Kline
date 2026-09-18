from datetime import UTC, datetime, timedelta

import structlog
from elasticsearch import NotFoundError

logger = structlog.get_logger()

SEEN_INDEX = "siem-seen"


async def load_seen(es, name: str) -> set[str]:
    """Read a named set. Absent means empty, which is a legitimate first run."""
    try:
        doc = await es.get(index=SEEN_INDEX, id=name)
    except NotFoundError:
        return set()
    return set(doc["_source"].get("values") or [])


async def add_seen(es, name: str, values: set[str]) -> None:
    """Union new values into the set. A no-op when there is nothing to add."""
    if not values:
        return
    current = await load_seen(es, name)
    merged = current | values
    if merged == current:
        return
    await es.index(
        index=SEEN_INDEX,
        id=name,
        document={"values": sorted(merged), "updated_at": datetime.now(UTC).isoformat()},
        refresh=True,
    )


async def seed_seen_from_events(es, name: str, field: str, days: int) -> set[str]:
    """Populate a set from what already exists, so a first run is quiet.

    Without this the detector's first pass treats every device on the network
    as new and fires once per device. Those alerts are noise, and a detection
    that cries wolf on day one is switched off on day two.
    """
    since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    body = {
        "query": {"range": {"timestamp": {"gte": since}}},
        "size": 0,
        "aggs": {"vals": {"terms": {"field": field, "size": 1000}}},
    }
    result = await es.search(index="siem-events-*", body=body)
    buckets = result.get("aggregations", {}).get("vals", {}).get("buckets", [])
    values = {b["key"] for b in buckets if b.get("key")}
    await es.index(
        index=SEEN_INDEX,
        id=name,
        document={"values": sorted(values), "updated_at": datetime.now(UTC).isoformat()},
        refresh=True,
    )
    logger.info("seen_set_seeded", name=name, field=field, days=days, count=len(values))
    return values
