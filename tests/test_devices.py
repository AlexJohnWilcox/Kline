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
