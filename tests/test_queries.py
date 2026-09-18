import pytest

from siem.storage.queries import get_device_stats, get_event_stats, search_events


class CapturingES:
    """Captures the request body and returns a minimal well-formed response."""

    def __init__(self, total=813992, relation="eq"):
        self.bodies = []
        self._total = total
        self._relation = relation

    async def search(self, index=None, body=None, **kw):
        self.bodies.append(body)
        return {
            "hits": {"total": {"value": self._total, "relation": self._relation},
                     "hits": []},
            "aggregations": {
                "by_source": {"buckets": []}, "by_severity": {"buckets": []},
                "by_category": {"buckets": []}, "by_host": {"buckets": []},
                "timeline": {"buckets": []},
            },
        }


@pytest.mark.asyncio
async def test_search_events_asks_for_the_real_total():
    es = CapturingES()
    await search_events(es)
    assert es.bodies[0]["track_total_hits"] is True


@pytest.mark.asyncio
async def test_search_events_returns_a_count_above_the_10k_ceiling():
    es = CapturingES(total=813992)
    _, total = await search_events(es)
    assert total == 813992


@pytest.mark.asyncio
async def test_event_stats_asks_for_the_real_total():
    es = CapturingES()
    await get_event_stats(es, hours=24)
    assert es.bodies[0]["track_total_hits"] is True


@pytest.mark.asyncio
async def test_filters_still_build_the_same_query():
    """The flag must not disturb the query that was already correct."""
    es = CapturingES()
    await search_events(es, host="192.168.10.241", source="pihole")
    must = es.bodies[0]["query"]["bool"]["must"]
    assert {"term": {"host": "192.168.10.241"}} in must
    assert {"term": {"source": "pihole"}} in must


class DeviceES:
    """Two searches: the events aggregation, then the open-alert counts."""

    def __init__(self, buckets, alert_buckets=None):
        self._buckets = buckets
        self._alerts = alert_buckets or []
        self.indices = []

    async def search(self, index=None, body=None, **kw):
        self.indices.append(index)
        if index and "alerts" in index:
            return {"hits": {"total": {"value": 0}},
                    "aggregations": {"by_host": {"buckets": self._alerts}}}
        return {"hits": {"total": {"value": 0}, "hits": []},
                "aggregations": {"by_host": {"buckets": self._buckets}}}


def _bucket(key, total, blocked, last_ms):
    return {"key": key, "doc_count": total,
            "blocked": {"doc_count": blocked},
            "last_seen": {"value": last_ms,
                          "value_as_string": "2026-09-18T12:00:00.000Z"}}


@pytest.mark.asyncio
async def test_devices_are_returned_busiest_first():
    es = DeviceES([_bucket("192.168.10.203", 500, 50, 1.0),
                   _bucket("192.168.10.241", 100, 40, 1.0)])
    rows = await get_device_stats(es)
    assert [r["host"] for r in rows] == ["192.168.10.203", "192.168.10.241"]


@pytest.mark.asyncio
async def test_blocked_share_is_a_percentage_of_that_device():
    es = DeviceES([_bucket("192.168.10.241", 100, 40, 1.0)])
    assert (await get_device_stats(es))[0]["blocked_pct"] == 40.0


@pytest.mark.asyncio
async def test_a_device_with_no_events_does_not_divide_by_zero():
    es = DeviceES([_bucket("192.168.10.9", 0, 0, None)])
    assert (await get_device_stats(es))[0]["blocked_pct"] == 0.0


@pytest.mark.asyncio
async def test_open_alerts_are_counted_per_device():
    es = DeviceES(
        [_bucket("192.168.10.241", 100, 40, 1.0), _bucket("192.168.10.3", 10, 0, 1.0)],
        alert_buckets=[{"key": "192.168.10.241", "doc_count": 4}],
    )
    rows = {r["host"]: r for r in await get_device_stats(es)}
    assert rows["192.168.10.241"]["open_alerts"] == 4
    assert rows["192.168.10.3"]["open_alerts"] == 0


@pytest.mark.asyncio
async def test_last_seen_is_the_formatted_timestamp_not_epoch_millis():
    es = DeviceES([_bucket("192.168.10.241", 5, 0, 1789740000000.0)])
    assert (await get_device_stats(es))[0]["last_seen"] == "2026-09-18T12:00:00.000Z"


@pytest.mark.asyncio
async def test_a_device_that_never_reported_has_no_last_seen():
    es = DeviceES([_bucket("192.168.10.9", 0, 0, None)])
    assert (await get_device_stats(es))[0]["last_seen"] is None


@pytest.mark.asyncio
async def test_alerts_are_read_from_the_alert_indices():
    es = DeviceES([_bucket("192.168.10.241", 1, 0, 1.0)])
    await get_device_stats(es)
    assert any("alerts" in (i or "") for i in es.indices)


@pytest.mark.asyncio
async def test_the_alert_aggregation_uses_the_keyword_subfield():
    """A terms agg on the analysed field errors with "Fielddata is disabled".

    Verified against the live index. This assertion exists because the failure
    is caught and swallowed at runtime, so getting the field wrong would show
    up as every device reporting zero open alerts rather than as an error.
    """

    class BodyCapturingES(DeviceES):
        def __init__(self):
            super().__init__([_bucket("192.168.10.241", 1, 0, 1.0)])
            self.alert_body = None

        async def search(self, index=None, body=None, **kw):
            if index and "alerts" in index:
                self.alert_body = body
            return await super().search(index=index, body=body, **kw)

    es = BodyCapturingES()
    await get_device_stats(es)
    field = es.alert_body["aggs"]["by_host"]["terms"]["field"]
    assert field == "context.hosts.keyword"


@pytest.mark.asyncio
async def test_resolved_alerts_are_excluded_from_the_count():
    """Open alerts are counted; resolved ones must not be. The fixture
    does not vary status, so this test would pass even if the must_not
    clause were dropped — hence we assert the clause is in the query.
    """

    class BodyCapturingES(DeviceES):
        def __init__(self):
            super().__init__([_bucket("192.168.10.241", 1, 0, 1.0)])
            self.alert_body = None

        async def search(self, index=None, body=None, **kw):
            if index and "alerts" in index:
                self.alert_body = body
            return await super().search(index=index, body=body, **kw)

    es = BodyCapturingES()
    await get_device_stats(es)
    must_not = es.alert_body["query"]["bool"]["must_not"]
    assert {"term": {"status": "resolved"}} in must_not


# ── Degrade paths must not invent facts ──


@pytest.mark.asyncio
async def test_unreadable_alerts_report_unknown_not_zero():
    """A failed alert lookup is not "no open alerts".

    Zero is an assertion about the alert index; the panel had no business
    making it after the aggregation raised.
    """

    class AlertsDownES(DeviceES):
        async def search(self, index=None, body=None, **kw):
            if index and "alerts" in index:
                raise RuntimeError("no alert index / fielddata disabled")
            return await super().search(index=index, body=body, **kw)

    es = AlertsDownES([_bucket("192.168.10.241", 100, 40, 1.0)])
    assert (await get_device_stats(es))[0]["open_alerts"] is None


@pytest.mark.asyncio
async def test_a_readable_but_silent_alert_index_still_reports_zero():
    """Unknown is only for failure. An answer of "none" is still zero."""
    es = DeviceES([_bucket("192.168.10.241", 100, 40, 1.0)], alert_buckets=[])
    assert (await get_device_stats(es))[0]["open_alerts"] == 0


@pytest.mark.asyncio
async def test_no_event_indices_yet_is_an_empty_panel_not_a_500():
    """ES omits "aggregations" when the wildcard matches nothing at all,
    which is every fresh install before the first event lands."""

    class FreshInstallES:
        async def search(self, index=None, body=None, **kw):
            return {"hits": {"total": {"value": 0}, "hits": []}}

    assert await get_device_stats(FreshInstallES()) == []
