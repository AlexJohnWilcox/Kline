import pytest
from elasticsearch import NotFoundError

from siem.storage.seen import add_seen, load_seen, seed_seen_from_events


class FakeES:
    def __init__(self, stored=None, buckets=None):
        self.stored = stored
        self.indexed = []
        self._buckets = buckets or []

    async def get(self, index, id):
        if self.stored is None:
            raise NotFoundError("not found", {}, {})
        return {"_source": {"values": sorted(self.stored)}}

    async def index(self, index, id, document, refresh=False):
        self.indexed.append((index, id, document))
        self.stored = set(document["values"])

    async def search(self, index=None, body=None, **kw):
        return {"hits": {"total": {"value": 0}, "hits": []},
                "aggregations": {"vals": {"buckets": self._buckets}}}


@pytest.mark.asyncio
async def test_an_absent_set_loads_as_none_not_an_error():
    """None, not set(): "never seeded" and "seeded, found nothing" are
    different answers, and a caller that cannot tell them apart re-seeds
    forever. See test_new_client_seeding."""
    assert await load_seen(FakeES(), "clients") is None


@pytest.mark.asyncio
async def test_a_stored_but_empty_set_is_not_the_same_as_an_absent_one():
    es = FakeES(stored=set())
    loaded = await load_seen(es, "clients")
    assert loaded is not None
    assert loaded == set()


@pytest.mark.asyncio
async def test_values_round_trip():
    es = FakeES()
    await add_seen(es, "clients", {"192.168.10.3"})
    assert await load_seen(es, "clients") == {"192.168.10.3"}


@pytest.mark.asyncio
async def test_adding_is_a_union_not_a_replacement():
    es = FakeES(stored={"a"})
    await add_seen(es, "clients", {"b"})
    assert await load_seen(es, "clients") == {"a", "b"}


@pytest.mark.asyncio
async def test_adding_nothing_does_not_write():
    es = FakeES(stored={"a"})
    await add_seen(es, "clients", set())
    assert es.indexed == []


@pytest.mark.asyncio
async def test_seeding_reads_the_window_and_stores_what_it_finds():
    es = FakeES(buckets=[{"key": "192.168.10.3"}, {"key": "192.168.10.241"}])
    seeded = await seed_seen_from_events(es, "clients", "parsed.client", days=30)
    assert seeded == {"192.168.10.3", "192.168.10.241"}
    assert await load_seen(es, "clients") == seeded


@pytest.mark.asyncio
async def test_seeding_writes_to_the_seen_index_under_the_given_name():
    es = FakeES(buckets=[{"key": "x"}])
    await seed_seen_from_events(es, "clients", "parsed.client", days=30)
    index, doc_id, _ = es.indexed[0]
    assert (index, doc_id) == ("siem-seen", "clients")
