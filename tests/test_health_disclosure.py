"""/api/v1/health is public, so it must not name filesystem paths.

The endpoint is in _AUTH_PUBLIC_PATHS. Adding collector status to it also
added blind_reason, which is built from configured paths -- "no readable
paths among: /var/log/syslog, /var/log/gate.log", or "permission denied
reading /var/log/gate.log: [Errno 13] ...". An anonymous caller learned the
deployment's log layout and which files the service cannot read.

The verdict is what a liveness check needs; the reason moved to the
authenticated /api/v1/collectors/status.
"""

import pytest

import siem.api.health as health_api
from siem.collectors.base import BaseCollector
from siem.main import _AUTH_PUBLIC_PATHS


class Blinded(BaseCollector):
    async def collect(self):
        return
        yield  # pragma: no cover


class FakeRunner:
    def __init__(self, collectors):
        self._collectors = collectors

    def status(self):
        return [c.status() for c in self._collectors]


@pytest.fixture
def blind_runner(monkeypatch):
    import siem.main

    collector = Blinded(name="syslog")
    collector.mark_blind("no readable paths among: /var/log/syslog, /var/log/gate.log")
    monkeypatch.setattr(siem.main, "collector_runner", FakeRunner([collector]))
    return collector


@pytest.mark.asyncio
async def test_the_public_endpoint_reports_blindness_without_the_reason(blind_runner):
    status = await health_api.health_check()

    collectors = status["collectors"]
    assert collectors[0]["health"] == "blind"
    assert "blind_reason" not in collectors[0]
    assert "/var/log" not in str(status)


@pytest.mark.asyncio
async def test_the_public_endpoint_still_degrades_on_blindness(blind_runner):
    """Hiding the reason must not hide the fact."""
    status = await health_api.health_check()

    assert status["status"] == "degraded"


@pytest.mark.asyncio
async def test_the_authenticated_endpoint_keeps_the_reason(blind_runner):
    collectors = await health_api.collectors_status()

    assert "/var/log/gate.log" in collectors[0]["blind_reason"]


def test_the_detailed_endpoint_is_not_public():
    assert "/api/v1/collectors/status" not in _AUTH_PUBLIC_PATHS
    assert "/api/v1/health" in _AUTH_PUBLIC_PATHS
