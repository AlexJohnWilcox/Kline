"""Resolve LAN addresses to the names the sanctum already knows.

The roster is not Kline's to maintain. The Gate holds the DHCP reservations
and the Oracle keeps a 30-day ledger of everything else, and collect.sh
already merges the two into the dashboard's data.json every 30 seconds. Kline
reads that and nothing more.
"""

import ssl
from datetime import UTC, datetime

import httpx
import structlog
from elasticsearch import NotFoundError

logger = structlog.get_logger()


def parse_roster(payload: dict) -> dict[str, str]:
    """Build {ip: name} from the sanctum's data.json.

    Bound souls are applied after wanderers, so a reservation's name wins over
    a ledger entry for the same address. An entry with no address is useless
    here and is skipped; one with no name falls back to its MAC, which is what
    the dashboard itself shows for a nameless wanderer.
    """
    if not isinstance(payload, dict):
        return {}
    out: dict[str, str] = {}
    for key in ("wanderers", "devices"):
        entries = payload.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            if not ip:
                continue
            label = entry.get("name") or entry.get("mac")
            if not label:
                continue
            out[str(ip)] = str(label)
    return out


DEVICE_INDEX = "siem-devices"
ROSTER_DOC_ID = "roster"


class DeviceResolver:
    """Keeps an IP->name map fetched from the sanctum's dashboard.

    Every failure path degrades to the last known map, and an empty map means
    every host renders as its raw address - which is what Kline did before
    this existed, so the worst case is no worse than before.
    """

    def __init__(self, url: str, ca_path: str | None = None, timeout: float = 5.0):
        self.url = url
        self.names: dict[str, str] = {}
        # When self.names was last fetched from the roster, ISO-8601 UTC, or
        # None for "never fetched in this process and nothing dated in the
        # cache". Names outlive their fetch - load() restores them across a
        # restart and refresh() keeps them through an outage - so without a
        # date the UI cannot tell current names from months-old ones.
        self.fetched_at: str | None = None
        # Caddy serves dash.lan with its internal CA, and httpx verifies
        # against certifi's bundle rather than the system trust store, so the
        # root has to be handed over explicitly. The dashboard publishes it.
        # verify=False is not an option: this response names every device on
        # the network.
        #
        # An SSLContext, not the bare path: httpx 0.28 deprecates verify=<str>
        # and will drop it. create_default_context raises here for a missing
        # or malformed file (FileNotFoundError / ssl.SSLError, both OSError),
        # which is what api.devices.build_resolver already catches.
        verify: ssl.SSLContext | bool = (
            ssl.create_default_context(cafile=ca_path) if ca_path else True
        )
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=3.0), verify=verify
        )

    async def load(self, es) -> dict[str, str]:
        """Read the cached map. Absent means 'never fetched', which is {}."""
        try:
            doc = await es.get(index=DEVICE_INDEX, id=ROSTER_DOC_ID)
        except NotFoundError:
            return {}
        except Exception:
            logger.exception("device_roster_cache_read_failed")
            return {}
        source = doc["_source"]
        self.names = dict(source.get("names") or {})
        # Absent in documents written before the field existed: the names are
        # still usable, their age is simply unknown, and None says so.
        self.fetched_at = source.get("fetched_at") or None
        return self.names

    async def refresh(self, es) -> dict[str, str]:
        """Fetch, cache and return. Never raises; never empties a good map."""
        try:
            resp = await self._client.get(self.url)
            resp.raise_for_status()
            names = parse_roster(resp.json())
        except Exception as exc:  # noqa: BLE001
            # Deliberately blind: the contract is "never raises to the
            # caller", not "never raises for exception types we predicted".
            # httpx.InvalidURL and httpx.CookieConflict, for example, are
            # Exception subclasses that don't derive from httpx.HTTPError,
            # so a narrower catch lets a config typo (a malformed
            # device_roster_url, which is an unvalidated plain str) escape
            # refresh() and kill Task 6's bare `while True: await
            # resolver.refresh(es)` loop for the life of the process. A
            # blind catch here is what keeps a config mistake as a logged
            # failure rather than a permanently dead background task.
            logger.warning(
                "device_roster_fetch_failed",
                url=self.url,
                error=str(exc),
                retained=len(self.names),
            )
            return self.names

        if not names:
            logger.warning("device_roster_empty", url=self.url)
            return self.names

        self.names = names
        # Dated at the fetch, not at the cache write: a failed write must not
        # leave the in-memory map claiming to be older than it is.
        self.fetched_at = datetime.now(UTC).isoformat()
        try:
            await es.index(
                index=DEVICE_INDEX,
                id=ROSTER_DOC_ID,
                document={"names": names, "fetched_at": self.fetched_at},
                refresh=False,
            )
        except Exception:
            logger.exception("device_roster_cache_write_failed")
        logger.info("device_roster_refreshed", count=len(names))
        return self.names

    async def aclose(self) -> None:
        await self._client.aclose()
