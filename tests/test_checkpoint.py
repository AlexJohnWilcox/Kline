import pytest
from elasticsearch import ConnectionError

from siem.storage.checkpoint import get_checkpoint, set_checkpoint


class FakeES:
    """Minimal stand-in for AsyncElasticsearch get/index on one document."""

    def __init__(self, docs=None):
        self.docs = docs or {}
        self.indexed = []

    async def get(self, index, id):
        if id not in self.docs:
            from elasticsearch import NotFoundError

            raise NotFoundError("not found", {}, {})
        return {"_source": {"value": self.docs[id]}}

    async def index(self, index, id, document, refresh=False):
        self.docs[id] = document["value"]
        self.indexed.append((index, id, document))


class FakeESWithConnectionError:
    """FakeES that raises ConnectionError on get."""

    async def get(self, index, id):
        raise ConnectionError("Connection refused")


@pytest.mark.asyncio
async def test_missing_checkpoint_reads_as_zero():
    es = FakeES()
    assert await get_checkpoint(es, "pihole_rowid") == 0


@pytest.mark.asyncio
async def test_checkpoint_round_trips():
    es = FakeES()
    await set_checkpoint(es, "pihole_rowid", 1275906)
    assert await get_checkpoint(es, "pihole_rowid") == 1275906


@pytest.mark.asyncio
async def test_checkpoint_writes_to_the_state_index():
    es = FakeES()
    await set_checkpoint(es, "pihole_rowid", 42)
    index, doc_id, document = es.indexed[0]
    assert index == "siem-state"
    assert doc_id == "pihole_rowid"
    assert document["value"] == 42


@pytest.mark.asyncio
async def test_connection_error_propagates():
    """ConnectionError from Elasticsearch should propagate, not be swallowed as 0."""
    es = FakeESWithConnectionError()
    with pytest.raises(ConnectionError):
        await get_checkpoint(es, "pihole_rowid")
