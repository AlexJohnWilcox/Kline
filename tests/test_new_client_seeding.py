"""Seeding must happen once, not on every pass forever.

load_seen returned set() both for an absent document and for a stored but
empty one, and check_new_clients branched on `if not seen`. With
NEW_CLIENT_ENABLED and no Pi-hole data -- or any 30-day window with no
parsed.client values -- it re-seeded every 300 seconds, logged
seen_set_seeded with count=0 at info, returned [], and never detected
anything. Success, reported, doing nothing.
"""

import pytest

from siem.detection import new_client


class SeedingES:
    """ES stand-in that remembers whether the seen document exists."""

    def __init__(self, stored=None, clients=()):
        self.stored = stored  # None = document absent
        self.clients = list(clients)
        self.alerts = []

    async def get(self, index, id):
        from elasticsearch import NotFoundError

        if self.stored is None:
            raise NotFoundError("not found", {}, {})
        return {"_source": {"values": sorted(self.stored)}}

    async def search(self, index=None, body=None, **kw):
        if index == "siem-suppressions":
            return {"hits": {"total": {"value": 0}, "hits": []}}
        buckets = [{"key": c} for c in self.clients]
        return {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {
                "clients": {"buckets": buckets},
                "vals": {"buckets": buckets},
            },
        }

    async def index(self, index, id=None, document=None, refresh=False, **kw):
        if index == "siem-seen":
            self.stored = set(document["values"])
        else:
            self.alerts.append(document)


@pytest.fixture
def seed_calls(monkeypatch):
    """Count seed runs specifically -- add_seen writes to the same index,
    so counting writes would not tell the two apart."""
    calls = []
    real = new_client.seed_seen_from_events

    async def counting(*args, **kwargs):
        calls.append(args)
        return await real(*args, **kwargs)

    monkeypatch.setattr(new_client, "seed_seen_from_events", counting)
    return calls


@pytest.mark.asyncio
async def test_the_first_pass_seeds_rather_than_alerting(seed_calls):
    es = SeedingES(stored=None, clients=["192.168.10.3"])

    assert await new_client.check_new_clients(es) == []

    assert len(seed_calls) == 1
    assert es.alerts == []


@pytest.mark.asyncio
async def test_an_empty_window_seeds_once_and_then_detects(seed_calls):
    """The defect: a seed that found nothing looked identical to no seed."""
    es = SeedingES(stored=None, clients=[])

    await new_client.check_new_clients(es)
    assert len(seed_calls) == 1
    assert es.stored == set()

    # Second pass: the set is empty but it HAS been seeded, so the detector
    # must move on to detecting rather than seeding again.
    es.clients = ["192.168.10.99"]
    found = await new_client.check_new_clients(es)

    assert len(seed_calls) == 1, "re-seeded a set that was already seeded"
    assert found == ["192.168.10.99"]
    assert len(es.alerts) == 1


@pytest.mark.asyncio
async def test_a_seeded_set_is_never_re_seeded(seed_calls):
    es = SeedingES(stored={"192.168.10.3"}, clients=["192.168.10.3"])

    assert await new_client.check_new_clients(es) == []

    assert seed_calls == []
