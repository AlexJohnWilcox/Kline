import asyncio
from datetime import UTC, datetime, timedelta

import structlog

from config.settings import settings
from siem.detection.engine import check_suppressions
from siem.models.alert import Alert
from siem.models.event import EventSeverity
from siem.storage.es_client import get_es_client
from siem.storage.indices import get_alert_index
from siem.storage.seen import add_seen, load_seen, seed_seen_from_events

logger = structlog.get_logger()

SEEN_NAME = "dns_clients"
CLIENT_FIELD = "parsed.client"
RULE_ID = "dns-new-client"
RULE_NAME = "A Device Not Seen Before"


async def find_new_clients(es, seen: set[str], hours: int) -> set[str]:
    """Clients that appeared in the window and are not in the set."""
    since = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
    body = {
        "query": {"range": {"timestamp": {"gte": since}}},
        "size": 0,
        "aggs": {"clients": {"terms": {"field": CLIENT_FIELD, "size": 500}}},
    }
    result = await es.search(index="siem-events-*", body=body)
    buckets = result.get("aggregations", {}).get("clients", {}).get("buckets", [])
    present = {b["key"] for b in buckets if b.get("key")}
    return present - seen


async def check_new_clients(es) -> list[str]:
    """One pass. Seeds on first run, alerts on each genuinely new client."""
    seen = await load_seen(es, SEEN_NAME)
    if not seen:
        # First run. Adopt the existing population rather than alerting on all
        # of it - see seed_seen_from_events.
        await seed_seen_from_events(es, SEEN_NAME, CLIENT_FIELD,
                                    settings.new_client_seed_days)
        return []

    hours = max(1, settings.new_client_interval_seconds // 3600 + 1)
    new = await find_new_clients(es, seen, hours=hours)
    for client in sorted(new):
        description = (
            f"{client} resolved a name and is absent from the "
            f"{settings.new_client_seed_days}-day roster of known clients."
        )
        # The alert context a suppression is matched against. "hosts" is the
        # key Suppression.matches_context reads for a host field, and it is
        # the only identifying value this detector has.
        context = {"hosts": [client], "event_count": 0}

        # This detector writes alerts itself rather than going through
        # DetectionEngine._raise_alert, so it has to consult suppressions
        # itself too. Without this the Alerts page happily creates a
        # suppression from a dns-new-client alert, stores it, lists it in
        # the Suppressions tab -- and nothing ever reads it.
        #
        # No AI budget: unlike a grouped rule, which can reach here once per
        # bucket inside a 30s loop, this raises at most a handful of alerts
        # every five minutes.
        suppression_msg = await check_suppressions(
            RULE_ID, RULE_NAME, description, context, es=es
        )

        alert = Alert(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            severity=EventSeverity.MEDIUM,
            description=description,
            matched_events=[],
            context=context,
            status="resolved" if suppression_msg else "new",
            resolution_reason=suppression_msg,
            ai_explanation=suppression_msg,
        )
        await es.index(index=get_alert_index(), id=alert.id, document=alert.to_es_doc())
        if suppression_msg:
            logger.info(
                "new_client_alert_suppressed",
                client=client,
                alert_id=alert.id,
                msg=suppression_msg,
            )
        else:
            logger.info("new_client_alert", client=client)

    await add_seen(es, SEEN_NAME, new)
    return sorted(new)


async def new_client_loop() -> None:
    """Background pass. Never raises: a detector that dies is worse than one
    that misses a cycle, and nothing above this restarts it."""
    if not settings.new_client_enabled:
        logger.info("new_client_detection_disabled")
        return
    es = await get_es_client()
    while True:
        try:
            await check_new_clients(es)
        except Exception:
            # Deliberately blind: nothing above this loop restarts it, so a
            # detector that dies on an unexpected exception is worse than one
            # that just misses a cycle. logger.exception keeps the traceback,
            # which is also why ruff's BLE001 doesn't fire here and no noqa
            # is needed for it.
            logger.exception("new_client_check_failed")
        await asyncio.sleep(settings.new_client_interval_seconds)
