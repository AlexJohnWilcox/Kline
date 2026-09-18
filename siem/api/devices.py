import asyncio

import structlog
from fastapi import APIRouter, Query

from config.settings import settings
from siem.enrich.devices import DeviceResolver
from siem.storage.es_client import get_es_client
from siem.storage.queries import get_device_stats

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


def build_resolver(url: str, ca_path: str | None) -> DeviceResolver | None:
    """Construct the roster resolver, degrading instead of crashing the app.

    httpx validates ca_path synchronously inside AsyncClient.__init__: a
    DEVICE_ROSTER_CA pointing at a missing or unreadable file raises
    FileNotFoundError (or an ssl.SSLError for an unreadable/malformed file -
    also an OSError subclass) right here, at construction time. Built
    unguarded at module level, that would crash the entire application on
    startup - syslog collection, detection, the UI, all of it - over an
    optional display feature's stale certificate path, even when
    device_names_enabled is False and the feature is not in use.

    Returning None instead of raising lets the app start with names simply
    unavailable: hosts render as raw addresses, exactly like before this
    feature existed. list_devices() copes with a None resolver. This does
    NOT weaken certificate verification - a valid ca_path is still required
    and verify=False is never used; an unusable path just means the roster
    fetch never happens, which refresh() already treats as a normal failure
    mode.
    """
    try:
        return DeviceResolver(url=url, ca_path=ca_path)
    except OSError as exc:
        logger.error(
            "device_roster_ca_unusable",
            ca_path=ca_path,
            error=str(exc),
            hint="device names disabled; hosts will render as raw addresses "
            "until DEVICE_ROSTER_CA points at a readable CA file",
        )
        return None


resolver = build_resolver(settings.device_roster_url, settings.device_roster_ca)


def attach_names(rows: list[dict], names: dict[str, str]) -> list[dict]:
    """Label rows for display. Returns copies: the rows are query results."""
    return [{**row, "name": names.get(row["host"])} for row in rows]


@router.get("")
async def list_devices(hours: int = Query(24, ge=1, le=720)) -> dict:
    es = await get_es_client()
    rows = await get_device_stats(es, hours=hours)
    names = resolver.names if resolver is not None else {}
    return {
        "devices": attach_names(rows, names),
        "resolved": bool(names),
        # When those names were last fetched, so the panel can say how old
        # they are. Cached names survive a restart and an indefinite outage,
        # so "resolved" alone would present months-old naming as current.
        # None means unknown: never fetched, or cached before this was dated.
        "names_as_of": resolver.fetched_at if resolver is not None else None,
    }


async def device_refresh_loop() -> None:
    """Keep the roster current. Failures are the resolver's problem, not ours."""
    if not settings.device_names_enabled:
        logger.info("device_names_disabled")
        return
    if resolver is None:
        logger.error("device_roster_refresh_loop_skipped", reason="resolver_unavailable")
        return
    es = await get_es_client()
    await resolver.load(es)
    while True:
        await resolver.refresh(es)
        await asyncio.sleep(settings.device_roster_refresh_seconds)
