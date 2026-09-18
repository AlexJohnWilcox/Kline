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


import httpx
import pytest

from siem.enrich.devices import DeviceResolver


class FakeES:
    def __init__(self, stored=None):
        self.stored = stored
        self.indexed = []

    async def get(self, index, id):
        if self.stored is None:
            from elasticsearch import NotFoundError

            raise NotFoundError("not found", {}, {})
        return {"_source": {"names": self.stored}}

    async def index(self, index, id, document, refresh=False):
        self.indexed.append((index, id, document))
        self.stored = document["names"]


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
