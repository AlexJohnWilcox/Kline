from datetime import UTC, datetime

import structlog

from siem.models.event import Event, EventCategory, EventSeverity

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
