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

# Generous bound for a query over a home LAN: long enough for the sqlite3
# call itself, short enough that a wedged ssh session (or a remote sudo
# unexpectedly reading a password from stdin) doesn't hang the collector
# forever with is_running still True and nothing logged.
SSH_TIMEOUT_SECONDS = 30

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


def _rowid_of(line: str) -> int | None:
    """Best-effort rowid extraction, independent of parse_ftl_line.

    parse_ftl_line rejects a row for reasons that have nothing to do with
    whether the rowid itself is readable (missing domain/client, wrong
    field count from a partial line, etc). If a whole batch is rejected,
    the collector must still be able to advance past it using the rowid
    alone -- otherwise it re-fetches and re-rejects the same rows forever,
    silently.
    """
    first = line.split(FTL_FIELD_SEP, 1)[0]
    try:
        return int(first)
    except ValueError:
        return None


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
        # These land unquoted in a remote shell string (SELECT_ROWS' LIMIT,
        # SELECT_BACKFILL_START's day count); coercing here is cheap
        # insurance against that ever becoming an injection vector.
        self.batch_size = int(batch_size)
        self.backfill_days = int(backfill_days)

    async def _run_sql(self, sql: str) -> str:
        """Run one statement against the Oracle's FTL database over SSH."""
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        if self.ssh_key:
            cmd += ["-i", self.ssh_key]
        # "--" so a hostname beginning with "-" can't be read as an ssh option.
        cmd += [
            "--",
            self.ssh_host,
            f"sudo sqlite3 -readonly -separator $'\\x1f' {FTL_DB} \"{sql}\"",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=SSH_TIMEOUT_SECONDS
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning(
                "pihole_ssh_timeout",
                host=self.ssh_host,
                timeout=SSH_TIMEOUT_SECONDS,
            )
            raise RuntimeError(
                f"pihole query timed out after {SSH_TIMEOUT_SECONDS}s"
            ) from None
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
                    resolved = await get_checkpoint(es, CHECKPOINT_NAME)
                    if resolved == 0:
                        resolved = await self._starting_point()
                        logger.info(
                            "pihole_backfill_start",
                            cursor=resolved,
                            days=self.backfill_days,
                        )
                    # Commit to `cursor` only once both the checkpoint read
                    # and (on a cold start) the backfill lookup have fully
                    # succeeded. Assigning `cursor` from get_checkpoint
                    # eagerly and only then calling _starting_point() would
                    # leave `cursor == 0` if the latter raised -- not None
                    # -- so this retry block would never re-fire and the
                    # next pass would silently read the whole database
                    # (WHERE id > 0) instead of the bounded backfill window.
                    cursor = resolved
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
                # Advance past a row by rowid even when parse_ftl_line
                # rejects it (bad domain/client, wrong field count). A
                # rowid is the SQL primary key, not user-controlled content,
                # so it is readable independent of the rest of the row. If a
                # whole batch is rejected, this is what keeps the collector
                # from re-fetching and re-rejecting the same rows forever,
                # silently.
                row_id = _rowid_of(line)
                if row_id is not None:
                    highest = max(highest, row_id)
                event = parse_ftl_line(line)
                if event is None:
                    continue
                yielded += 1
                yield event

            if out.strip() and yielded == 0:
                # Either every row in a non-empty batch was malformed, or
                # (more likely on a non-bash login shell) the remote
                # $'\x1f' ANSI-C quoting wasn't expanded and every field
                # count check is failing. Either way this is worth a human
                # noticing.
                logger.warning(
                    "pihole_batch_all_unparseable", host=self.ssh_host
                )

            advanced = False
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
                    advanced = True
                    logger.debug("pihole_batch", count=yielded, cursor=cursor)

            # A full batch means we are behind; keep draining without
            # sleeping -- but only when the cursor actually advanced. A
            # persistent checkpoint-write failure must still sleep, or it
            # turns into a tight re-fetch/re-yield loop limited only by SSH
            # round-trip time.
            if yielded < self.batch_size or not advanced:
                await asyncio.sleep(self.poll_seconds)
