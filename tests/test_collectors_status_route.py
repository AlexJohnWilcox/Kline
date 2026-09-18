"""One handler for /api/v1/collectors/status, with the published shape.

The path had two handlers: the original in siem/main.py, returning
{"collectors": [...]} since commit 4158da9, and a second added later in
siem/api/health.py returning a bare [...]. Routers are included before the
@app.get runs, so the newcomer won at dispatch -- the original became dead
code and the JSON contract changed silently, with nothing to notice.

{"collectors": [...]} is the published shape and is what survives. The
surviving handler must still carry blind_reason (the point of the second
one) and must still be authenticated (blind_reason names filesystem
paths).

These drive the endpoint through the real ASGI stack rather than calling
the function, because "which of the two handlers answers" is precisely
what was wrong and only dispatch can answer it.
"""

import base64
import json

import itsdangerous
import pytest
from fastapi.testclient import TestClient

import siem.api.health as health_api
import siem.main
from config.settings import settings
from siem.collectors.base import BaseCollector
from siem.main import _AUTH_PUBLIC_PATHS, app

PATH = "/api/v1/collectors/status"
REASON = "no readable paths among: /var/log/syslog"


class Blinded(BaseCollector):
    async def collect(self):
        return
        yield  # pragma: no cover


class FakeRunner:
    def __init__(self, collectors):
        self._collectors = collectors

    def status(self):
        return [c.status() for c in self._collectors]


def _client():
    # No `with`: the lifespan is deliberately not run. It would open
    # Elasticsearch connections and start the collectors; routing and the
    # auth middleware need neither.
    return TestClient(app)


def _signed_in(client):
    """A session cookie the SessionMiddleware will accept, without ES."""
    signer = itsdangerous.TimestampSigner(str(settings.session_secret))
    payload = base64.b64encode(json.dumps({"user_id": "u1"}).encode())
    client.cookies.set(settings.session_cookie_name, signer.sign(payload).decode())
    return client


@pytest.fixture
def blind_runner(monkeypatch):
    collector = Blinded(name="syslog")
    collector.mark_blind(REASON)
    monkeypatch.setattr(siem.main, "collector_runner", FakeRunner([collector]))
    return collector


def test_the_health_router_does_not_also_bind_the_path():
    """Two handlers on one path is the kind of thing that survives until
    somebody edits the wrong one."""
    assert [r for r in health_api.router.routes if r.path == PATH] == []


def test_the_response_is_an_object_keyed_collectors(blind_runner):
    """The published contract, asserted as a shape rather than by eye. The
    shadowing handler returned a bare list."""
    resp = _signed_in(_client()).get(PATH, headers={"accept": "application/json"})

    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, dict), body
    assert list(body) == ["collectors"]
    assert body["collectors"][0]["name"] == "syslog"


def test_the_response_carries_blind_reason(blind_runner):
    """The reason the second handler was written; it must not be lost with
    it."""
    resp = _signed_in(_client()).get(PATH, headers={"accept": "application/json"})

    entry = resp.json()["collectors"][0]
    assert entry["health"] == "blind"
    assert entry["blind_reason"] == REASON


def test_an_unauthenticated_caller_does_not_get_it(blind_runner):
    """blind_reason names the deployment's log layout."""
    resp = _client().get(PATH, headers={"accept": "application/json"})

    assert resp.status_code == 401
    assert "/var/log" not in resp.text


def test_the_path_is_not_public():
    assert PATH not in _AUTH_PUBLIC_PATHS
