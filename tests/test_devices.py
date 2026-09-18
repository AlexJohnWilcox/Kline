from siem.enrich.devices import parse_roster

# Shaped exactly like the real https://dash.lan/data.json, trimmed.
SAMPLE = {
    "ts": 1789740000,
    "devices": [
        {"name": "oracle", "ip": "192.168.10.2", "mac": "88:a2:9e:c3:5b:07"},
        {"name": "erebus", "ip": "192.168.10.203", "mac": "b4:2e:99:e2:e9:3d"},
        {"name": "scrying-glass", "ip": "192.168.10.241", "mac": "58:96:0a:f8:18:6f"},
    ],
    "wanderers": [
        {"name": "Alex Mac", "ip": "192.168.10.145", "mac": "52:d0:61:4a:26:56",
         "present": False},
        {"name": "", "ip": "192.168.10.99", "mac": "aa:bb:cc:dd:ee:ff"},
        {"name": "no address", "mac": "11:22:33:44:55:66"},
    ],
    "wards": {"kline": "aglow"},
}


def test_bound_souls_and_wanderers_are_both_included():
    m = parse_roster(SAMPLE)
    assert m["192.168.10.2"] == "oracle"
    assert m["192.168.10.241"] == "scrying-glass"
    assert m["192.168.10.145"] == "Alex Mac"


def test_a_nameless_wanderer_falls_back_to_its_mac():
    assert parse_roster(SAMPLE)["192.168.10.99"] == "aa:bb:cc:dd:ee:ff"


def test_an_entry_with_no_address_is_skipped():
    assert "no address" not in parse_roster(SAMPLE).values()


def test_empty_and_malformed_payloads_yield_an_empty_map_not_an_error():
    assert parse_roster({}) == {}
    assert parse_roster({"devices": None, "wanderers": None}) == {}
    assert parse_roster({"devices": [{"junk": 1}]}) == {}
    assert parse_roster({"devices": "not a list"}) == {}


def test_a_device_never_overwrites_itself_with_a_worse_name():
    """A bound soul's name wins over a wanderer entry for the same address."""
    payload = {
        "devices": [{"name": "erebus", "ip": "192.168.10.203"}],
        "wanderers": [{"name": "", "ip": "192.168.10.203", "mac": "b4:2e:99:e2:e9:3d"}],
    }
    assert parse_roster(payload)["192.168.10.203"] == "erebus"


def test_malformed_top_level_payloads_yield_empty_map():
    """Non-dict payloads are handled gracefully, not raised."""
    assert parse_roster(None) == {}
    assert parse_roster([]) == {}
    assert parse_roster("not a dict") == {}
    assert parse_roster(42) == {}


from datetime import UTC, datetime

import httpx
import pytest

from siem.enrich.devices import DeviceResolver


class FakeES:
    def __init__(self, stored=None, fetched_at=None):
        self.stored = stored
        self.fetched_at = fetched_at
        self.indexed = []

    async def get(self, index, id):
        if self.stored is None:
            from elasticsearch import NotFoundError

            raise NotFoundError("not found", {}, {})
        source = {"names": self.stored}
        if self.fetched_at is not None:
            source["fetched_at"] = self.fetched_at
        return {"_source": source}

    async def index(self, index, id, document, refresh=False):
        self.indexed.append((index, id, document))
        self.stored = document["names"]
        self.fetched_at = document.get("fetched_at")


def _resolver(handler):
    r = DeviceResolver(url="https://dash.lan/data.json")
    r._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return r


@pytest.mark.asyncio
async def test_a_good_fetch_populates_and_caches():
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(200, json=SAMPLE))
    names = await r.refresh(es)
    assert names["192.168.10.241"] == "scrying-glass"
    assert r.names["192.168.10.241"] == "scrying-glass"
    index, doc_id, doc = es.indexed[0]
    assert (index, doc_id) == ("siem-devices", "roster")
    assert doc["names"]["192.168.10.2"] == "oracle"


@pytest.mark.asyncio
async def test_a_failed_fetch_keeps_the_last_good_map():
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(200, json=SAMPLE))
    await r.refresh(es)

    r._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: (_ for _ in ()).throw(httpx.ConnectError("down"))
        )
    )
    names = await r.refresh(es)
    assert names["192.168.10.241"] == "scrying-glass", "a blip must not erase names"


@pytest.mark.asyncio
async def test_a_failed_fetch_with_no_prior_map_yields_empty_not_an_exception():
    es = FakeES()
    r = _resolver(lambda req: (_ for _ in ()).throw(httpx.ConnectError("down")))
    assert await r.refresh(es) == {}


@pytest.mark.asyncio
async def test_a_non_200_is_a_failure_not_a_parse():
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(502, text="erebus asleep"))
    assert await r.refresh(es) == {}


@pytest.mark.asyncio
async def test_unparseable_json_is_a_failure_not_a_crash():
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(200, text="<html>nope</html>"))
    assert await r.refresh(es) == {}


@pytest.mark.asyncio
async def test_the_cached_map_is_loaded_on_startup():
    es = FakeES(stored={"192.168.10.241": "scrying-glass"})
    r = DeviceResolver(url="https://dash.lan/data.json")
    assert (await r.load(es))["192.168.10.241"] == "scrying-glass"


@pytest.mark.asyncio
async def test_no_cache_yet_loads_as_empty():
    r = DeviceResolver(url="https://dash.lan/data.json")
    assert await r.load(FakeES()) == {}


@pytest.mark.asyncio
async def test_a_malformed_roster_url_fails_before_any_transport_and_does_not_raise():
    """device_roster_url is a bare, unvalidated str: a typo raises out of
    httpx's own URL parsing (e.g. httpx.InvalidURL), never reaching the
    MockTransport the other tests go through. refresh() must still degrade
    instead of letting that escape and kill the caller's refresh loop.
    """
    es = FakeES()
    r = DeviceResolver(url="http://[::1")
    assert await r.refresh(es) == {}


@pytest.mark.asyncio
async def test_a_malformed_roster_url_does_not_erase_a_prior_good_map():
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(200, json=SAMPLE))
    await r.refresh(es)

    r.url = "http://[::1"
    names = await r.refresh(es)
    assert names["192.168.10.241"] == "scrying-glass"


# ── The names have to carry their age ──
#
# Cached names survive a restart and an unbounded outage. Undated, the panel
# presents a map fetched months ago exactly as it presents one fetched a
# minute ago - the same silent drift the spec rejected a static config map
# for.


@pytest.mark.asyncio
async def test_a_good_fetch_dates_the_cache_document():
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(200, json=SAMPLE))
    await r.refresh(es)
    _, _, doc = es.indexed[0]
    assert "fetched_at" in doc, "undated names cannot be aged by the UI"
    stamped = datetime.fromisoformat(doc["fetched_at"])
    assert abs((datetime.now(UTC) - stamped).total_seconds()) < 60
    assert r.fetched_at == doc["fetched_at"]


@pytest.mark.asyncio
async def test_the_cached_names_come_back_with_their_date():
    es = FakeES(
        stored={"192.168.10.241": "scrying-glass"},
        fetched_at="2026-07-01T12:00:00+00:00",
    )
    r = DeviceResolver(url="https://dash.lan/data.json")
    await r.load(es)
    assert r.fetched_at == "2026-07-01T12:00:00+00:00"


@pytest.mark.asyncio
async def test_a_cache_written_before_dates_existed_loads_as_unknown_age():
    es = FakeES(stored={"192.168.10.241": "scrying-glass"})
    r = DeviceResolver(url="https://dash.lan/data.json")
    assert await r.load(es) == {"192.168.10.241": "scrying-glass"}
    assert r.fetched_at is None, "unknown age must not read as fresh"


@pytest.mark.asyncio
async def test_never_having_fetched_is_an_unknown_date_not_now():
    assert DeviceResolver(url="https://dash.lan/data.json").fetched_at is None


@pytest.mark.asyncio
async def test_a_failed_fetch_does_not_freshen_the_date():
    """Retained names keep the date of the fetch that produced them."""
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(200, json=SAMPLE))
    await r.refresh(es)
    first = r.fetched_at

    r._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: (_ for _ in ()).throw(httpx.ConnectError("down"))
        )
    )
    await r.refresh(es)
    assert r.fetched_at == first


@pytest.mark.asyncio
async def test_an_empty_roster_does_not_freshen_the_date_either():
    es = FakeES()
    r = _resolver(lambda req: httpx.Response(200, json=SAMPLE))
    await r.refresh(es)
    first = r.fetched_at

    r._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={}))
    )
    await r.refresh(es)
    assert r.fetched_at == first
