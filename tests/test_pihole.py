from datetime import UTC

from siem.collectors.pihole import FTL_FIELD_SEP, parse_ftl_line
from siem.models.event import EventCategory, EventSeverity


def _line(rowid="1", ts="1789652189.06513", qtype="1", status="2",
          domain="example.com", client="192.168.10.203", forward="10.2.0.1#53",
          reply_type="4"):
    return FTL_FIELD_SEP.join(
        [rowid, ts, qtype, status, domain, client, forward, reply_type]
    )


def test_forwarded_query_maps_to_a_low_dns_event():
    event = parse_ftl_line(_line())
    assert event is not None
    assert event.source == "pihole"
    assert event.host == "192.168.10.203"
    assert event.category == EventCategory.DNS
    assert event.severity == EventSeverity.LOW
    assert event.message == "example.com"
    assert event.parsed["blocked"] is False
    assert event.parsed["query_type"] == "A"
    assert event.parsed["upstream"] == "10.2.0.1#53"
    assert event.parsed["ftl_rowid"] == 1


def test_gravity_blocked_query_is_medium_and_tagged():
    event = parse_ftl_line(_line(status="1", forward=""))
    assert event.severity == EventSeverity.MEDIUM
    assert event.parsed["blocked"] is True
    assert "blocked" in event.tags
    assert event.parsed["upstream"] is None


def test_regex_block_also_counts_as_blocked():
    assert parse_ftl_line(_line(status="4")).parsed["blocked"] is True


def test_cached_query_is_not_blocked():
    assert parse_ftl_line(_line(status="3")).parsed["blocked"] is False


def test_timestamp_is_parsed_as_utc():
    event = parse_ftl_line(_line(ts="1789652189.06513"))
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset().total_seconds() == 0
    assert event.timestamp.year == 2026


def test_unknown_query_type_falls_back_to_other():
    assert parse_ftl_line(_line(qtype="99")).parsed["query_type"] == "OTHER"


def test_https_query_type():
    assert parse_ftl_line(_line(qtype="16")).parsed["query_type"] == "HTTPS"


def test_nxdomain_is_flagged_from_reply_type_not_status():
    # FTL carries NXDOMAIN in reply_type (2), never in status. Measured
    # 2026-09-17: status 8 does not occur at all; reply_type 2 is 3,386/day.
    assert parse_ftl_line(_line(reply_type="2")).parsed["nxdomain"] is True
    assert parse_ftl_line(_line(reply_type="4")).parsed["nxdomain"] is False
    assert parse_ftl_line(_line(reply_type="2")).parsed["reply_type"] == 2


def test_malformed_lines_are_skipped_not_raised():
    assert parse_ftl_line("") is None
    assert parse_ftl_line("only\x1ftwo") is None
    assert parse_ftl_line(_line(ts="not-a-number")) is None
    assert parse_ftl_line(_line(rowid="x")) is None
    assert parse_ftl_line(_line(reply_type="x")) is None


def test_rows_without_a_domain_or_client_are_skipped():
    assert parse_ftl_line(_line(domain="")) is None
    assert parse_ftl_line(_line(client="")) is None


def test_dns_is_a_real_category():
    assert EventCategory.DNS.value == "dns"
