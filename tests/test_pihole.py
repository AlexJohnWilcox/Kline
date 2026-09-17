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


import pytest

from siem.collectors.pihole import PiholeCollector, next_checkpoint


def test_checkpoint_advances_normally():
    assert next_checkpoint(1000, 1500) == 1000


def test_checkpoint_resets_when_the_database_rolled():
    # FTL vacuumed and rowids restarted below our cursor. Without this guard
    # the collector reads nothing, forever, and says nothing about it.
    assert next_checkpoint(1_275_906, 400) == 0


def test_checkpoint_holds_when_max_equals_cursor():
    assert next_checkpoint(500, 500) == 500


def test_empty_database_does_not_trigger_a_reset():
    # max_rowid of 0 means "no rows yet", not "rolled over".
    assert next_checkpoint(500, 0) == 500


@pytest.mark.asyncio
async def test_collect_yields_events_and_advances_the_cursor(monkeypatch):
    """Drive two batches.

    The cursor is written after a batch finishes, not per event, so the
    assertion has to be made once the third event proves batch one completed.
    Breaking at event two would abandon the generator before set_checkpoint
    ran and the cursor would never be written at all.
    """
    collector = PiholeCollector(ssh_host="oracle", poll_seconds=0, batch_size=2)
    all_rows = {
        10: _line(rowid="10", domain="a.example", status="2"),
        11: _line(rowid="11", domain="b.example", status="1"),
        12: _line(rowid="12", domain="c.example", status="2"),
    }

    async def fake_run(self, sql):
        if "MAX(id)" in sql:
            return "12"
        after = int(sql.split("id > ")[1].split(" ")[0])
        due = [all_rows[k] for k in sorted(all_rows) if k > after][:2]
        return "\n".join(due)

    saved = {}

    async def fake_get(es, name):
        return saved.get(name, 0)

    async def fake_set(es, name, value):
        saved[name] = value

    async def fake_es_client():
        return object()

    monkeypatch.setattr(PiholeCollector, "_run_sql", fake_run)
    monkeypatch.setattr("siem.collectors.pihole.get_checkpoint", fake_get)
    monkeypatch.setattr("siem.collectors.pihole.set_checkpoint", fake_set)
    monkeypatch.setattr("siem.collectors.pihole.get_es_client", fake_es_client)

    collected = []
    async for event in collector.collect():
        collected.append(event)
        if len(collected) == 3:
            break

    assert [e.message for e in collected] == [
        "a.example", "b.example", "c.example",
    ]
    # Batch one (rows 10-11) completed and wrote its cursor before batch two.
    assert saved["pihole_rowid"] == 11


@pytest.mark.asyncio
async def test_a_cold_start_is_bounded_to_the_backfill_window(monkeypatch):
    """_starting_point is tested directly.

    Driving collect() for this would mean asserting on a generator that
    yields nothing and then sleeps forever.
    """
    collector = PiholeCollector(ssh_host="oracle", backfill_days=30)
    seen = {}

    async def fake_run(self, sql):
        seen["sql"] = sql
        return "1000000\n"

    monkeypatch.setattr(PiholeCollector, "_run_sql", fake_run)

    # Exclusive cursor: one below the first in-window row, so that row is read.
    assert await collector._starting_point() == 999_999
    assert "-30 day" in seen["sql"]


@pytest.mark.asyncio
async def test_a_cold_start_on_an_empty_database_starts_at_zero(monkeypatch):
    collector = PiholeCollector(ssh_host="oracle", backfill_days=30)

    async def fake_run(self, sql):
        return "0\n"

    monkeypatch.setattr(PiholeCollector, "_run_sql", fake_run)
    assert await collector._starting_point() == 0


@pytest.mark.asyncio
async def test_checkpoint_read_failure_at_startup_does_not_escape_collect_and_recovers(
    monkeypatch,
):
    """An ES outage at startup must retry, not kill the collector.

    get_checkpoint propagates transport errors now (only NotFoundError means
    0). Without a retry around the startup read, BaseCollector.start's bare
    `except Exception` would catch it once and the collector would never run
    again for the life of the process -- exactly the case after the
    workstation's nightly poweroff, when ES may still be coming up.
    """
    collector = PiholeCollector(ssh_host="oracle", poll_seconds=0, batch_size=2)
    all_rows = {
        10: _line(rowid="10", domain="a.example", status="2"),
        11: _line(rowid="11", domain="b.example", status="1"),
        12: _line(rowid="12", domain="c.example", status="2"),
    }

    async def fake_run(self, sql):
        if "MAX(id)" in sql:
            return "12"
        after = int(sql.split("id > ")[1].split(" ")[0])
        due = [all_rows[k] for k in sorted(all_rows) if k > after][:2]
        return "\n".join(due)

    calls = {"get_checkpoint": 0}

    async def fake_get(es, name):
        calls["get_checkpoint"] += 1
        if calls["get_checkpoint"] == 1:
            raise ConnectionError("es unreachable")
        return 9

    saved = {}

    async def fake_set(es, name, value):
        saved[name] = value

    async def fake_es_client():
        return object()

    monkeypatch.setattr(PiholeCollector, "_run_sql", fake_run)
    monkeypatch.setattr("siem.collectors.pihole.get_checkpoint", fake_get)
    monkeypatch.setattr("siem.collectors.pihole.set_checkpoint", fake_set)
    monkeypatch.setattr("siem.collectors.pihole.get_es_client", fake_es_client)

    collected = []
    async for event in collector.collect():
        collected.append(event)
        if len(collected) == 3:
            break

    # The first get_checkpoint call raised and did not escape collect(); the
    # second, on a later pass, succeeded and the collector proceeded normally.
    assert calls["get_checkpoint"] == 2
    assert [e.message for e in collected] == [
        "a.example", "b.example", "c.example",
    ]
    assert saved["pihole_rowid"] == 11


@pytest.mark.asyncio
async def test_a_failed_checkpoint_write_holds_the_cursor_so_the_next_pass_rereads(
    monkeypatch,
):
    """Duplicates beat gaps.

    If set_checkpoint fails after a batch, the in-memory cursor must not
    advance -- otherwise the next pass would read starting after rows that
    were never durably recorded as seen, producing a silent gap. Holding the
    cursor means the same row is re-yielded (a duplicate) instead.
    """
    collector = PiholeCollector(ssh_host="oracle", poll_seconds=0, batch_size=1)
    all_rows = {
        10: _line(rowid="10", domain="a.example", status="2"),
        11: _line(rowid="11", domain="b.example", status="1"),
    }

    async def fake_run(self, sql):
        if "MAX(id)" in sql:
            return "11"
        after = int(sql.split("id > ")[1].split(" ")[0])
        due = [all_rows[k] for k in sorted(all_rows) if k > after][:1]
        return "\n".join(due)

    async def fake_get(es, name):
        return 9

    set_calls = []

    async def fake_set(es, name, value):
        set_calls.append(value)
        if len(set_calls) == 1:
            raise ConnectionError("es unreachable")

    async def fake_es_client():
        return object()

    monkeypatch.setattr(PiholeCollector, "_run_sql", fake_run)
    monkeypatch.setattr("siem.collectors.pihole.get_checkpoint", fake_get)
    monkeypatch.setattr("siem.collectors.pihole.set_checkpoint", fake_set)
    monkeypatch.setattr("siem.collectors.pihole.get_es_client", fake_es_client)

    collected = []
    async for event in collector.collect():
        collected.append(event)
        if len(collected) == 3:
            break

    # Row 10 is re-yielded because the first set_checkpoint(10) failed and
    # the cursor was held at 9, not advanced.
    assert [e.parsed["ftl_rowid"] for e in collected] == [10, 10, 11]
    # The first write attempt failed; the retry on the next pass succeeded.
    assert set_calls == [10, 10]
