"""A syslog line stamped now must reach Elasticsearch stamped now.

The BSD and OpenWrt syslog formats carry local wall-clock time and no UTC
offset. Parsing them into a naive datetime and serialising that with
.isoformat() hands Elasticsearch an offset-less date, which it reads as UTC
-- backdating every event by the local offset. Detection windows are 300 and
900 seconds, so a four-hour backdate means no syslog rule can ever fire,
while the collector reports healthy and the events are visible in the UI.

These tests assert the *value* that reaches Elasticsearch, not the parsed
wall-clock components: asserting components is what let the defect through.
"""

from datetime import UTC, datetime, timedelta, timezone

from siem.collectors.syslog import parse_syslog_line


def _local_now() -> datetime:
    """Now, as an aware datetime in this host's own zone."""
    return datetime.now(UTC).astimezone()


def test_a_bsd_line_stamped_now_lands_at_now():
    now = _local_now()
    line = (
        now.strftime("%b %d %H:%M:%S")
        + " gate dropbear[1]: Bad password attempt for 'root' from 1.2.3.4:5"
    )

    event = parse_syslog_line(line)

    assert event is not None
    assert event.timestamp.tzinfo is not None, "a naive timestamp is read as UTC by ES"
    assert abs((event.timestamp - now).total_seconds()) < 2


def test_an_openwrt_line_stamped_now_lands_at_now():
    now = _local_now()
    line = (
        now.strftime("%a %b %d %H:%M:%S %Y")
        + " daemon.notice rotate-road[1]: FAIL US-VA did not carry traffic"
    )

    event = parse_syslog_line(line)

    assert event is not None
    assert event.timestamp.tzinfo is not None
    assert abs((event.timestamp - now).total_seconds()) < 2


def test_the_document_elasticsearch_receives_carries_an_offset():
    """to_es_doc() is where the defect actually bit: .isoformat() on a naive
    value emits no offset and ES then assumes UTC."""
    now = _local_now()
    line = now.strftime("%b %d %H:%M:%S") + " gate sshd[1]: Accepted publickey for nyx"

    doc = parse_syslog_line(line).to_es_doc()

    reparsed = datetime.fromisoformat(doc["timestamp"])
    assert reparsed.tzinfo is not None, f"no offset in {doc['timestamp']!r}"
    assert abs((reparsed - now).total_seconds()) < 2


def test_a_fresh_syslog_event_is_inside_a_five_minute_detection_window():
    """The end-to-end consequence: this is the check build_rule_query makes."""
    now = _local_now()
    line = now.strftime("%b %d %H:%M:%S") + " gate sshd[1]: Failed password for root"

    event = parse_syslog_line(line)

    window_start = datetime.now(UTC) - timedelta(seconds=300)
    assert event.timestamp >= window_start


def test_an_iso_line_with_its_own_offset_is_not_shifted_twice():
    stamped = datetime(2026, 4, 8, 18, 35, 58, 88727, tzinfo=timezone(-timedelta(hours=4)))
    line = f"{stamped.isoformat()} erebus sshd[1]: Accepted publickey for nyx"

    event = parse_syslog_line(line)

    assert event.timestamp == stamped
    assert event.timestamp.astimezone(UTC).hour == 22


def test_a_bsd_line_keeps_its_local_wall_clock_reading():
    """The stored value is UTC, but converting it back must give the clock
    time the line was written with."""
    now = _local_now()
    line = now.strftime("%b %d %H:%M:%S") + " gate sshd[1]: hello"

    local = parse_syslog_line(line).timestamp.astimezone()

    assert (local.hour, local.minute, local.second) == (now.hour, now.minute, now.second)


def test_no_bsd_line_is_ever_stamped_a_year_in_the_future():
    """A BSD line carries no year. On 1 January a "Dec 31" line inherits the
    new year and lands twelve months ahead -- as invisible to a 300s window
    as the four-hour backdate was."""
    now = datetime.now(UTC)
    for stamp in ("Dec 31 23:59:59", "Jan 01 00:00:01", "Jun 15 12:00:00"):
        event = parse_syslog_line(f"{stamp} gate sshd[1]: hello")
        assert event.timestamp - now < timedelta(days=1), stamp


def test_an_unparseable_timestamp_still_yields_an_aware_fallback():
    event = parse_syslog_line("Feb 30 25:99:99 gate sshd[1]: hello")
    if event is not None:
        assert event.timestamp.tzinfo is not None
