import asyncio
import re
from datetime import UTC, datetime, timedelta

import structlog

from config.settings import settings
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

# Daily event indices (siem-events-2026.09.17) and monthly alert indices
# (siem-alerts-2026.09). The day group is optional so both parse here.
INDEX_DATE_PATTERN = re.compile(r"^siem-(events|alerts)-(\d{4})\.(\d{2})(?:\.(\d{2}))?$")

# Run retention check once per day (in seconds)
RETENTION_CHECK_INTERVAL = 86400


def index_end_date(year: int, month: int, day: int | None) -> datetime:
    """The exclusive end of the period an index covers.

    A daily index ends the next day; a monthly one ends on the first of the
    next month. Retention compares this against the cutoff, so an index is
    only dropped once every document it could hold is older than the window.
    """
    if day is not None:
        return datetime(year, month, day, tzinfo=UTC) + timedelta(days=1)
    if month == 12:
        return datetime(year + 1, 1, 1, tzinfo=UTC)
    return datetime(year, month + 1, 1, tzinfo=UTC)


def should_delete(
    index_name: str, event_cutoff: datetime, alert_cutoff: datetime
) -> bool:
    """Whether an index is entirely older than its type's retention window."""
    match = INDEX_DATE_PATTERN.match(index_name)
    if not match:
        return False

    index_type = match.group(1)
    year = int(match.group(2))
    month = int(match.group(3))
    day = int(match.group(4)) if match.group(4) else None

    cutoff = event_cutoff if index_type == "events" else alert_cutoff
    # Compare dates, not instants, deliberately -- and not by accident of
    # the plan, which said instants. RETENTION_CHECK_INTERVAL is a plain
    # sleep(86400) anchored to whenever the process last started, so an
    # instant comparison would make "is this index old enough" depend on
    # the time of day the loop happens to fire: an index could survive one
    # pass and die on the next purely because the app was restarted at a
    # different hour. Truncating to dates costs up to ~24h of extra
    # retention and buys a decision that is the same whenever it is made.
    return index_end_date(year, month, day).date() < cutoff.date()


async def cleanup_old_indices() -> dict[str, list[str]]:
    """Delete Elasticsearch indices older than configured retention.

    Returns dict of deleted index names grouped by type.
    """
    es = await get_es_client()
    now = datetime.now(UTC)

    event_cutoff = now - timedelta(days=settings.event_retention_days)
    alert_cutoff = now - timedelta(days=settings.alert_retention_days)

    # Get all SIEM indices
    try:
        indices = await es.indices.get(index="siem-*")
    except Exception:
        logger.warning("retention_no_indices")
        return {"events": [], "alerts": []}

    deleted: dict[str, list[str]] = {"events": [], "alerts": []}

    for index_name in indices:
        match = INDEX_DATE_PATTERN.match(index_name)
        if not match:
            continue

        if not should_delete(index_name, event_cutoff, alert_cutoff):
            continue

        index_type = match.group(1)
        try:
            await es.indices.delete(index=index_name)
            deleted[index_type].append(index_name)
            logger.info("retention_deleted_index", index=index_name)
        except Exception:
            logger.exception("retention_delete_error", index=index_name)

    if deleted["events"] or deleted["alerts"]:
        logger.info(
            "retention_complete",
            deleted_events=len(deleted["events"]),
            deleted_alerts=len(deleted["alerts"]),
        )
    else:
        logger.debug("retention_nothing_to_delete")

    return deleted


async def retention_loop() -> None:
    """Background loop that periodically cleans up old indices."""
    # Wait a bit on startup before first check
    await asyncio.sleep(60)

    while True:
        try:
            await cleanup_old_indices()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("retention_loop_error")

        await asyncio.sleep(RETENTION_CHECK_INTERVAL)
