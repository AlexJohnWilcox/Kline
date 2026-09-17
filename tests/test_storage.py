from datetime import UTC, datetime

import pytest

from siem.models.event import Event, EventCategory, EventSeverity
from siem.storage.indices import get_alert_index, get_event_index
from siem.storage.queries import index_events_bulk


def test_event_index_is_daily():
    when = datetime(2026, 9, 17, 14, 30, tzinfo=UTC)
    assert get_event_index(when) == "siem-events-2026.09.17"


def test_event_index_defaults_to_now():
    assert get_event_index().startswith("siem-events-")
    assert len(get_event_index()) == len("siem-events-2026.09.17")


def test_alert_index_stays_monthly():
    when = datetime(2026, 9, 17, tzinfo=UTC)
    assert get_alert_index(when) == "siem-alerts-2026.09"


class FakeBulkES:
    """Records the operations handed to bulk() and replays a canned result."""

    def __init__(self, result=None):
        self.operations = None
        self._result = result if result is not None else {"errors": False}

    async def bulk(self, operations):
        self.operations = operations
        return self._result


def _event(when: datetime, domain: str = "a.example") -> Event:
    return Event(
        timestamp=when,
        source="pihole",
        host="192.168.10.203",
        severity=EventSeverity.LOW,
        category=EventCategory.DNS,
        message=domain,
    )


@pytest.mark.asyncio
async def test_a_batch_spanning_two_days_lands_in_two_daily_indices():
    """Regression: the batch's index used to be now(), not the event's day.

    Daily indices exist so retention can express "30 days" of event age.
    Routing on ingest time instead means a cold-start backfill writes a
    month of history into a single siem-events-<today>, which retention then
    holds for a further 30 days -- so the granularity the daily split was
    introduced for does not hold for exactly the data that needs it.
    """
    es = FakeBulkES()
    events = [
        _event(datetime(2026, 9, 16, 23, 59, tzinfo=UTC), "yesterday.example"),
        _event(datetime(2026, 9, 17, 0, 1, tzinfo=UTC), "today.example"),
    ]

    assert await index_events_bulk(es, events) == 2

    targets = [
        op["index"]["_index"] for op in es.operations if "index" in op
    ]
    assert targets == ["siem-events-2026.09.16", "siem-events-2026.09.17"]


@pytest.mark.asyncio
async def test_a_backfilled_event_does_not_land_in_todays_index():
    es = FakeBulkES()
    old = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)

    await index_events_bulk(es, [_event(old)])

    target = es.operations[0]["index"]["_index"]
    assert target == "siem-events-2026.08.20"
    assert target != get_event_index()


@pytest.mark.asyncio
async def test_an_empty_batch_indexes_nothing():
    es = FakeBulkES()
    assert await index_events_bulk(es, []) == 0
    assert es.operations is None


@pytest.mark.asyncio
async def test_partial_bulk_failures_are_subtracted_from_the_count():
    es = FakeBulkES(
        result={
            "errors": True,
            "items": [
                {"index": {"status": 201}},
                {"index": {"status": 429, "error": {"type": "rejected"}}},
            ],
        }
    )
    events = [
        _event(datetime(2026, 9, 17, 1, 0, tzinfo=UTC)),
        _event(datetime(2026, 9, 17, 2, 0, tzinfo=UTC)),
    ]
    assert await index_events_bulk(es, events) == 1
