import pytest

from siem.storage.queries import get_event_stats, search_events


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
