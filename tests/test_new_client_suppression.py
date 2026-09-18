"""dns-new-client alerts must consult suppressions like every other alert.

check_new_clients wrote alerts with es.index() directly, and the
suppression check lived as a private method with exactly one caller,
DetectionEngine._raise_alert. So a user who resolved a dns-new-client alert
and created a suppression from it got a success message from the UI, saw
the rule listed in the Suppressions tab, and nothing ever read it.
"""

from datetime import UTC, datetime, timedelta

import pytest

from siem.detection import new_client
from siem.detection.engine import (
    AI_SUPPRESSION_BUCKET_BUDGET,
    AiSuppressionBudget,
    DetectionEngine,
    check_suppressions,
)
from siem.models.rule import DetectionRule
from siem.models.suppression import Suppression


class RecordingES:
    """ES stand-in: one known client seen, one new one in the window."""

    def __init__(self, suppressions=(), seen=("192.168.10.3",)):
        self.indexed = []
        self._suppressions = list(suppressions)
        self._seen = set(seen)
        self.suppression_searches = 0

    async def get(self, index, id):
        return {"_source": {"values": sorted(self._seen)}}

    async def search(self, index=None, body=None, **kw):
        if index == "siem-suppressions":
            self.suppression_searches += 1
            hits = [
                {"_id": s.id, "_source": s.model_dump(mode="json")}
                for s in self._suppressions
            ]
            return {"hits": {"total": {"value": len(hits)}, "hits": hits}}
        return {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {
                "clients": {"buckets": [{"key": c} for c in [*self._seen, "192.168.10.99"]]}
            },
        }

    async def index(self, index, id=None, document=None, refresh=False, **kw):
        self.indexed.append((index, document))


def _suppression(**fields):
    return Suppression(
        rule_id="dns-new-client",
        reason="the new laptop, expected",
        source_alert_id="a" * 32,
        match_fields=fields,
        expires_at=datetime.now(UTC) + timedelta(days=7),
        status="active",
    )


def _alerts(es):
    return [doc for index, doc in es.indexed if index.startswith("siem-alerts")]


@pytest.mark.asyncio
async def test_a_new_client_alerts_when_nothing_suppresses_it():
    es = RecordingES()

    assert await new_client.check_new_clients(es) == ["192.168.10.99"]

    alerts = _alerts(es)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "dns-new-client"
    assert alerts[0]["status"] == "new"
    assert alerts[0]["resolution_reason"] is None


@pytest.mark.asyncio
async def test_the_suppression_index_is_actually_consulted():
    es = RecordingES()

    await new_client.check_new_clients(es)

    assert es.suppression_searches == 1, "the alert path never asked"


@pytest.mark.asyncio
async def test_a_matching_suppression_auto_resolves_the_alert():
    es = RecordingES(suppressions=[_suppression(host="192.168.10.99")])

    await new_client.check_new_clients(es)

    alert = _alerts(es)[0]
    assert alert["status"] == "resolved"
    assert "the new laptop, expected" in alert["resolution_reason"]


@pytest.mark.asyncio
async def test_a_suppression_for_a_different_client_does_not_resolve_it():
    es = RecordingES(suppressions=[_suppression(host="10.0.0.1")])

    await new_client.check_new_clients(es)

    alert = _alerts(es)[0]
    assert alert["status"] == "new"
    assert alert["resolution_reason"] is None


@pytest.mark.asyncio
async def test_the_engine_call_site_still_behaves_the_same_way():
    """The refactor must not change what DetectionEngine does. The AI budget
    is still per rule evaluation and still spent only at the fallback."""
    engine = DetectionEngine()
    engine._ai_suppression_budget = AiSuppressionBudget(1)
    rule = DetectionRule(
        id="dns-new-client",
        name="x",
        description="y",
        severity="medium",
        conditions=[],
    )

    # A deterministic match must not spend the budget.
    import siem.detection.engine as engine_module

    async def fake_client():
        return RecordingES(suppressions=[_suppression(host="192.168.10.99")])

    original = engine_module.get_es_client
    engine_module.get_es_client = fake_client
    try:
        msg = await engine._check_suppressions(rule, {"hosts": ["192.168.10.99"]})
    finally:
        engine_module.get_es_client = original

    assert msg is not None
    assert engine._ai_suppression_budget.remaining == 1


@pytest.mark.asyncio
async def test_the_budget_callback_stops_the_ai_fallback():
    """An exhausted budget returns None rather than calling the 10s matcher."""
    import siem.detection.engine as engine_module

    async def fake_client():
        return RecordingES(suppressions=[_suppression(host="10.0.0.1")])

    original = engine_module.get_es_client
    engine_module.get_es_client = fake_client
    try:
        msg = await check_suppressions(
            "dns-new-client", "x", "y", {"hosts": ["192.168.10.99"]},
            spend_ai_budget=lambda _rule_id: False,
        )
    finally:
        engine_module.get_es_client = original

    assert msg is None


# --- the AI fallback is bounded here too -----------------------------------


class ManyClientsES(RecordingES):
    """Several genuinely new clients in one pass, none of them matched
    deterministically by the active suppressions."""

    def __init__(self, suppressions, clients):
        super().__init__(suppressions=suppressions, seen=())
        self._clients = list(clients)

    async def get(self, index, id):
        return {"_source": {"values": []}}

    async def search(self, index=None, body=None, **kw):
        if index == "siem-suppressions":
            self.suppression_searches += 1
            hits = [
                {"_id": s.id, "_source": s.model_dump(mode="json")}
                for s in self._suppressions
            ]
            return {"hits": {"total": {"value": len(hits)}, "hits": hits}}
        return {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"clients": {"buckets": [{"key": c} for c in self._clients]}},
        }


@pytest.mark.asyncio
async def test_the_ai_fallback_is_bounded_for_new_clients_too(monkeypatch):
    """Unbounded, the cost here is new clients x active suppressions x the
    matcher's 10s timeout, serialised inside the detector's own interval:
    five clients against twenty suppressions is about seventeen minutes.
    """
    calls = []

    async def fake_ai_match(**kwargs):
        calls.append(kwargs["alert_context"])
        return False

    monkeypatch.setattr(
        "siem.ai.suppression_matcher.ai_match_suppression", fake_ai_match
    )
    suppressions = [_suppression(host="10.0.0.1"), _suppression(host="10.0.0.2")]
    es = ManyClientsES(suppressions, [f"192.168.10.{i}" for i in range(10)])

    await new_client.check_new_clients(es)

    # Ten clients would have cost 20 matcher calls. The budget is per pass,
    # and clients past it still got the deterministic match.
    assert len(calls) == AI_SUPPRESSION_BUCKET_BUDGET * len(suppressions)
    assert len(_alerts(es)) == 10, "every client still gets its alert"
