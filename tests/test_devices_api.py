import pytest

from siem.api.devices import attach_names, build_resolver, list_devices


def test_names_are_attached_without_touching_the_stored_rows():
    rows = [{"host": "192.168.10.241", "events": 100},
            {"host": "192.168.10.99", "events": 5}]
    named = attach_names(rows, {"192.168.10.241": "scrying-glass"})
    assert named[0]["name"] == "scrying-glass"
    assert named[1]["name"] is None


def test_attaching_names_does_not_mutate_the_input():
    rows = [{"host": "192.168.10.241", "events": 100}]
    attach_names(rows, {"192.168.10.241": "scrying-glass"})
    assert "name" not in rows[0], "rows come from Elasticsearch; do not mutate them"


def test_an_empty_map_leaves_every_row_unnamed():
    rows = [{"host": "192.168.10.241", "events": 100}]
    assert attach_names(rows, {})[0]["name"] is None


# ── CA-path correction ──
#
# The brief has the resolver built unguarded at module level:
#   resolver = DeviceResolver(url=..., ca_path=settings.device_roster_ca)
# httpx validates ca_path synchronously inside AsyncClient.__init__, so a bad
# DEVICE_ROSTER_CA (missing/unreadable file) raises FileNotFoundError right
# there - at import time, unconditionally, even when device_names_enabled is
# False. That would crash the whole app over an optional display feature.
# build_resolver() must degrade to None instead, and list_devices() must
# still return unnamed rows when it does.


def test_a_nonexistent_ca_path_does_not_raise_at_construction():
    assert build_resolver("https://dash.lan/data.json", "/no/such/ca.pem") is None


def test_a_valid_configuration_still_builds_a_real_resolver():
    from siem.enrich.devices import DeviceResolver

    assert isinstance(build_resolver("https://dash.lan/data.json", None), DeviceResolver)


class FakeES:
    """Minimal ES double for get_device_stats' two search calls."""

    async def search(self, index=None, body=None, **kw):
        if index == "siem-events-*":
            return {
                "aggregations": {
                    "by_host": {
                        "buckets": [
                            {
                                "key": "192.168.10.241",
                                "doc_count": 10,
                                "blocked": {"doc_count": 2},
                                "last_seen": {
                                    "value": 1,
                                    "value_as_string": "2026-09-18T00:00:00.000Z",
                                },
                            }
                        ]
                    }
                }
            }
        return {"aggregations": {"by_host": {"buckets": []}}}


@pytest.mark.asyncio
async def test_list_devices_still_returns_rows_when_the_resolver_could_not_be_built(
    monkeypatch,
):
    import siem.api.devices as devices_module

    monkeypatch.setattr(devices_module, "resolver", None)

    async def fake_get_es_client():
        return FakeES()

    monkeypatch.setattr(devices_module, "get_es_client", fake_get_es_client)

    result = await list_devices(hours=24)
    assert result["devices"][0]["host"] == "192.168.10.241"
    assert result["devices"][0]["name"] is None
    assert result["resolved"] is False
    assert result["names_as_of"] is None


# ── The response says how old the naming is, and no more ──


class StubResolver:
    def __init__(self, names, fetched_at):
        self.names = names
        self.fetched_at = fetched_at


@pytest.mark.asyncio
async def test_the_response_dates_the_names_it_resolved(monkeypatch):
    import siem.api.devices as devices_module

    monkeypatch.setattr(
        devices_module,
        "resolver",
        StubResolver({"192.168.10.241": "scrying-glass"}, "2026-07-01T12:00:00+00:00"),
    )

    async def fake_get_es_client():
        return FakeES()

    monkeypatch.setattr(devices_module, "get_es_client", fake_get_es_client)

    result = await list_devices(hours=24)
    assert result["resolved"] is True
    assert result["names_as_of"] == "2026-07-01T12:00:00+00:00"


@pytest.mark.asyncio
async def test_the_response_does_not_ship_the_whole_roster(monkeypatch):
    """Only the devices that reported events are the panel's business.

    The full map is payload nothing reads, and it discloses the names of
    devices that produced no events in the window.
    """
    import siem.api.devices as devices_module

    monkeypatch.setattr(
        devices_module,
        "resolver",
        StubResolver(
            {"192.168.10.241": "scrying-glass", "192.168.10.7": "quiet-one"},
            "2026-07-01T12:00:00+00:00",
        ),
    )

    async def fake_get_es_client():
        return FakeES()

    monkeypatch.setattr(devices_module, "get_es_client", fake_get_es_client)

    result = await list_devices(hours=24)
    assert "names" not in result
    assert "quiet-one" not in str(result)


# ── httpx 0.28 deprecates verify=<str> ──


@pytest.mark.filterwarnings("error::DeprecationWarning")
def test_a_ca_path_is_passed_as_an_ssl_context_not_a_deprecated_string():
    """verify=<str> warns today and goes away in a later httpx.

    filterwarnings turns that DeprecationWarning into an error, so this test
    fails against the string form rather than merely noting it in the run.
    """
    import ssl

    import certifi

    from siem.enrich.devices import DeviceResolver

    resolver = build_resolver("https://dash.lan/data.json", certifi.where())
    assert isinstance(resolver, DeviceResolver)
    assert isinstance(resolver._client._transport._pool._ssl_context, ssl.SSLContext)
