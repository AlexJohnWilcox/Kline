import pytest

from siem.detection.new_client import find_new_clients


class AggES:
    def __init__(self, keys):
        self._keys = keys

    async def search(self, index=None, body=None, **kw):
        return {"hits": {"total": {"value": 0}, "hits": []},
                "aggregations": {"clients": {"buckets": [{"key": k} for k in self._keys]}}}


@pytest.mark.asyncio
async def test_a_client_absent_from_the_set_is_new():
    es = AggES(["192.168.10.3", "192.168.10.99"])
    assert await find_new_clients(es, {"192.168.10.3"}, hours=1) == {"192.168.10.99"}


@pytest.mark.asyncio
async def test_nothing_is_new_when_everything_is_known():
    es = AggES(["a", "b"])
    assert await find_new_clients(es, {"a", "b"}, hours=1) == set()


@pytest.mark.asyncio
async def test_an_empty_seen_set_makes_every_client_new():
    """This is why seeding exists - never let this run unseeded in production."""
    es = AggES(["a", "b"])
    assert await find_new_clients(es, set(), hours=1) == {"a", "b"}


@pytest.mark.asyncio
async def test_no_traffic_yields_nothing_new():
    assert await find_new_clients(AggES([]), {"a"}, hours=1) == set()
