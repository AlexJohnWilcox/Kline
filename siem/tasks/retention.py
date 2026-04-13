import asyncio
import re
from datetime import UTC, datetime, timedelta

import structlog

from config.settings import settings
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

# Match index names like siem-events-2025.01 or siem-alerts-2025.03
INDEX_DATE_PATTERN = re.compile(r"^siem-(events|alerts)-(\d{4})\.(\d{2})$")

# Run retention check once per day (in seconds)
RETENTION_CHECK_INTERVAL = 86400


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

        index_type = match.group(1)  # "events" or "alerts"
        year = int(match.group(2))
        month = int(match.group(3))

        # Index covers the entire month — use last day of month
        if month == 12:
            index_end = datetime(year + 1, 1, 1, tzinfo=UTC)
        else:
            index_end = datetime(year, month + 1, 1, tzinfo=UTC)

        cutoff = event_cutoff if index_type == "events" else alert_cutoff

        if index_end < cutoff:
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
