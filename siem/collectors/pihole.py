import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import structlog

from siem.collectors.base import BaseCollector
from siem.models.event import Event, EventCategory, EventSeverity
from siem.storage.checkpoint import get_checkpoint, set_checkpoint
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

# ASCII unit separator. Domains, client names and upstreams can all contain
# a comma or a tab; none of them can contain this.
FTL_FIELD_SEP = "\x1f"

# FTL status codes that mean the query was answered by Pi-hole rather than
# forwarded: gravity, regex, denylist, and their CNAME-inherited variants.
FTL_BLOCKED_STATUSES = frozenset({1, 4, 5, 9, 10, 11})

FTL_QUERY_TYPES = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR", 7: "TXT",
    8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG", 12: "DNSKEY", 13: "NS",
    14: "OTHER", 15: "SVCB", 16: "HTTPS",
}

# NXDOMAIN lives in reply_type, not status. Measured on the Oracle
# 2026-09-17: status 8 does not occur in 24h at all, while reply_type 2
# accounts for 3,386 queries. A rule keyed on status would never fire.
FTL_REPLY_NXDOMAIN = 2

FTL_FIELD_COUNT = 8


def parse_ftl_line(line: str) -> Event | None:
    """Parse one row of the FTL `queries` view into an Event.

    Returns None for anything malformed. A collector reading a live database
    will occasionally see a partial line; that is not worth an exception.
    """
    parts = line.rstrip("\n").split(FTL_FIELD_SEP)
    if len(parts) != FTL_FIELD_COUNT:
        return None

    rowid, ts, qtype, status, domain, client, forward, reply = parts
    if not domain or not client:
        return None

    try:
        row_id = int(rowid)
        timestamp = datetime.fromtimestamp(float(ts), tz=UTC)
        type_code = int(qtype)
        status_code = int(status)
        reply_code = int(reply)
    except (ValueError, OSError, OverflowError):
        return None

    blocked = status_code in FTL_BLOCKED_STATUSES

    return Event(
        timestamp=timestamp,
        source="pihole",
        host=client,
        severity=EventSeverity.MEDIUM if blocked else EventSeverity.LOW,
        category=EventCategory.DNS,
        message=domain,
        parsed={
            "domain": domain,
            "client": client,
            "status": status_code,
            "blocked": blocked,
            "reply_type": reply_code,
            "nxdomain": reply_code == FTL_REPLY_NXDOMAIN,
            "query_type": FTL_QUERY_TYPES.get(type_code, "OTHER"),
            "upstream": forward or None,
            "ftl_rowid": row_id,
        },
        tags=["dns", "blocked"] if blocked else ["dns"],
        raw=line,
    )


CHECKPOINT_NAME = "pihole_rowid"
FTL_DB = "/etc/pihole/pihole-FTL.db"

SELECT_ROWS = (
    "SELECT id, timestamp, type, status, domain, client, "
    "COALESCE(forward, ''), COALESCE(reply_type, 0) FROM queries "
    "WHERE id > {after} ORDER BY id LIMIT {limit};"
)
SELECT_MAX = "SELECT COALESCE(MAX(id), 0) FROM queries;"
SELECT_BACKFILL_START = (
    "SELECT COALESCE(MIN(id), 0) FROM queries "
    "WHERE timestamp > strftime('%s', 'now', '-{days} day');"
)


def next_checkpoint(current: int, max_rowid: int) -> int:
    """Guard against FTL rolling or vacuuming its database.

    Pi-hole rotates pihole-FTL.db. If rowids restart below our cursor the
    collector would read nothing for as long as it took anyone to notice,
    which is how this class of collector fails silently. A max below the
    cursor means the database is not the one we were reading.
    """
    if max_rowid and max_rowid < current:
        logger.warning(
            "pihole_rowid_rollover", cursor=current, max_rowid=max_rowid
        )
        return 0
    return current


class PiholeCollector(BaseCollector):
    """Reads Pi-hole's query log from the Oracle, incrementally by rowid.

    A pull rather than a push: the checkpoint holds the cursor in
    Elasticsearch, so an Elasticsearch outage costs nothing and the missed
    queries are backfilled once it comes back.
    """

    def __init__(
        self,
        ssh_host: str,
        ssh_key: str | None = None,
        poll_seconds: int = 30,
        batch_size: int = 500,
        backfill_days: int = 30,
    ):
        super().__init__(name="pihole")
        self.ssh_host = ssh_host
        self.ssh_key = ssh_key
        self.poll_seconds = poll_seconds
        self.batch_size = batch_size
        self.backfill_days = backfill_days

    async def _run_sql(self, sql: str) -> str:
        """Run one statement against the Oracle's FTL database over SSH."""
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        if self.ssh_key:
            cmd += ["-i", self.ssh_key]
        cmd += [
            self.ssh_host,
            f"sudo sqlite3 -readonly -separator $'\\x1f' {FTL_DB} \"{sql}\"",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"pihole query failed ({proc.returncode}): "
                f"{stderr.decode(errors='replace').strip()}"
            )
        return stdout.decode(errors="replace")

    async def _starting_point(self) -> int:
        """Bound a cold start to backfill_days rather than the whole database."""
        out = await self._run_sql(
            SELECT_BACKFILL_START.format(days=self.backfill_days)
        )
        first = out.strip().splitlines()
        start = int(first[0]) if first and first[0].strip().isdigit() else 0
        # Exclusive cursor: start one below so the first matching row is read.
        return max(start - 1, 0)

    async def collect(self) -> AsyncIterator[Event]:
        es = None
        # None means "not yet established". Deferring the startup checkpoint
        # read (and the cold-start _starting_point call) into the loop below
        # means an Elasticsearch outage at startup -- e.g. right after the
        # nightly poweroff, while ES is still coming up -- logs and retries
        # instead of raising out of collect() and letting BaseCollector.start
        # catch it once and stop the collector for good.
        cursor = None

        while True:
            if cursor is None:
                try:
                    if es is None:
                        es = await get_es_client()
                    cursor = await get_checkpoint(es, CHECKPOINT_NAME)
                    if cursor == 0:
                        cursor = await self._starting_point()
                        logger.info(
                            "pihole_backfill_start",
                            cursor=cursor,
                            days=self.backfill_days,
                        )
                except Exception:
                    logger.exception(
                        "pihole_checkpoint_read_error", host=self.ssh_host
                    )
                    await asyncio.sleep(self.poll_seconds)
                    continue

            try:
                max_rowid = int((await self._run_sql(SELECT_MAX)).strip() or 0)
                reset = next_checkpoint(cursor, max_rowid)
                if reset != cursor:
                    # The database is not the one we were reading (FTL
                    # vacuumed/rolled). Holding the stale, too-high cursor
                    # would mean reading nothing forever -- a permanent gap,
                    # which is exactly what this guard exists to prevent -- so
                    # the in-memory cursor resets immediately. The persisted
                    # copy is best-effort here; a failure just means the next
                    # pass re-derives the same reset.
                    cursor = reset
                    try:
                        await set_checkpoint(es, CHECKPOINT_NAME, cursor)
                    except Exception:
                        logger.exception(
                            "pihole_checkpoint_write_error", host=self.ssh_host
                        )

                out = await self._run_sql(
                    SELECT_ROWS.format(after=cursor, limit=self.batch_size)
                )
            except Exception:
                logger.exception("pihole_fetch_error", host=self.ssh_host)
                await asyncio.sleep(self.poll_seconds)
                continue

            highest = cursor
            yielded = 0
            for line in out.splitlines():
                if not line.strip():
                    continue
                event = parse_ftl_line(line)
                if event is None:
                    continue
                highest = max(highest, event.parsed["ftl_rowid"])
                yielded += 1
                yield event

            if highest > cursor:
                # Advance the in-memory cursor only once the write succeeds.
                # If it fails, leave the cursor where it was so the next pass
                # re-reads this batch -- a duplicate, not a silent gap.
                try:
                    await set_checkpoint(es, CHECKPOINT_NAME, highest)
                except Exception:
                    logger.exception(
                        "pihole_checkpoint_write_error", host=self.ssh_host
                    )
                else:
                    cursor = highest
                    logger.debug("pihole_batch", count=yielded, cursor=cursor)

            # A full batch means we are behind; keep draining without sleeping.
            if yielded < self.batch_size:
                await asyncio.sleep(self.poll_seconds)
