"""Resolve LAN addresses to the names the sanctum already knows.

The roster is not Kline's to maintain. The Gate holds the DHCP reservations
and the Oracle keeps a 30-day ledger of everything else, and collect.sh
already merges the two into the dashboard's data.json every 30 seconds. Kline
reads that and nothing more.
"""


def parse_roster(payload: dict) -> dict[str, str]:
    """Build {ip: name} from the sanctum's data.json.

    Bound souls are applied after wanderers, so a reservation's name wins over
    a ledger entry for the same address. An entry with no address is useless
    here and is skipped; one with no name falls back to its MAC, which is what
    the dashboard itself shows for a nameless wanderer.
    """
    if not isinstance(payload, dict):
        return {}
    out: dict[str, str] = {}
    for key in ("wanderers", "devices"):
        entries = payload.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            if not ip:
                continue
            label = entry.get("name") or entry.get("mac")
            if not label:
                continue
            out[str(ip)] = str(label)
    return out
