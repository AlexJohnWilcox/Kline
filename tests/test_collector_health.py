from pathlib import Path

import pytest

from siem.collectors.base import BaseCollector
from siem.collectors.network import NetworkCollector
from siem.collectors.syslog import SyslogCollector


class Dummy(BaseCollector):
    async def collect(self):
        return
        yield  # pragma: no cover - makes this an async generator


def test_a_fresh_collector_is_stopped_not_blind():
    c = Dummy(name="dummy")
    assert c.health == "stopped"
    assert c.blind_reason is None


def test_a_blind_collector_reports_blind_and_why():
    c = Dummy(name="dummy")
    c.mark_blind("no readable paths among: /var/log/syslog")
    assert c.health == "blind"
    assert "var/log/syslog" in c.blind_reason


def test_blindness_survives_into_status():
    c = Dummy(name="dummy")
    c.mark_blind("nothing to read")
    s = c.status()
    assert s["health"] == "blind"
    assert s["blind_reason"] == "nothing to read"


def test_a_syslog_collector_with_no_existing_paths_is_blind_at_construction():
    c = SyslogCollector(paths=[Path("/nonexistent/one"), Path("/nonexistent/two")])
    assert c.health == "blind"
    assert "/nonexistent/one" in c.blind_reason


def test_a_syslog_collector_with_a_real_path_is_not_blind(tmp_path):
    p = tmp_path / "syslog"
    p.write_text("")
    c = SyslogCollector(paths=[p])
    assert c.health != "blind"
    assert c.blind_reason is None


def test_a_network_collector_with_no_existing_paths_is_blind():
    c = NetworkCollector(firewall_paths=[Path("/nonexistent/kern.log")])
    assert c.health == "blind"


@pytest.mark.asyncio
async def test_running_wins_over_stopped_once_started():
    c = Dummy(name="dummy")
    c._running = True
    assert c.health == "ok"
