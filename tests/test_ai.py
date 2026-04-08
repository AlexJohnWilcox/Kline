import json
from unittest.mock import AsyncMock, patch

import pytest

from siem.ai.client import OllamaClient, OllamaError
from siem.ai.nl_query import _fallback_query, _validate_es_query


# ── Ollama Client ──


@pytest.fixture
def ollama_client():
    return OllamaClient(base_url="http://localhost:11434", model="test-model", timeout=10.0)


async def test_ollama_generate(ollama_client, httpx_mock):
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": "Hello from LLM", "done": True},
    )
    result = await ollama_client.generate("test prompt")
    assert result == "Hello from LLM"
    await ollama_client.close()


async def test_ollama_generate_json_mode(ollama_client, httpx_mock):
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": '{"query": {"match_all": {}}}', "done": True},
    )
    result = await ollama_client.generate("test", json_mode=True)
    parsed = json.loads(result)
    assert "query" in parsed

    # Verify json format was requested
    request = httpx_mock.get_request()
    body = json.loads(request.content)
    assert body["format"] == "json"
    await ollama_client.close()


async def test_ollama_generate_with_system(ollama_client, httpx_mock):
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": "response", "done": True},
    )
    await ollama_client.generate("prompt", system="system prompt")
    request = httpx_mock.get_request()
    body = json.loads(request.content)
    assert body["system"] == "system prompt"
    await ollama_client.close()


async def test_ollama_unavailable(ollama_client, httpx_mock):
    httpx_mock.add_exception(ConnectionError("refused"))
    with pytest.raises(OllamaError):
        await ollama_client.generate("test")
    await ollama_client.close()


async def test_ollama_is_available_true(ollama_client, httpx_mock):
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": []},
    )
    assert await ollama_client.is_available() is True
    await ollama_client.close()


async def test_ollama_is_available_false(ollama_client, httpx_mock):
    httpx_mock.add_exception(ConnectionError("refused"))
    assert await ollama_client.is_available() is False
    await ollama_client.close()


# ── NL Query Validation ──


def test_validate_es_query_valid():
    assert _validate_es_query({"query": {"match_all": {}}}) is True


def test_validate_es_query_missing_query_key():
    assert _validate_es_query({"match_all": {}}) is False


def test_validate_es_query_not_dict():
    assert _validate_es_query("not a dict") is False


def test_validate_es_query_blocks_scripts():
    assert _validate_es_query({"query": {"script": {"source": "bad"}}}) is False


def test_validate_es_query_blocks_delete():
    assert _validate_es_query({"query": {"match_all": {}}, "delete_by_query": True}) is False


def test_fallback_query():
    q = _fallback_query("failed SSH logins")
    assert q["query"]["multi_match"]["query"] == "failed SSH logins"
    assert "message" in q["query"]["multi_match"]["fields"]


# ── Summarizer ──


async def test_summarize_events_ollama_down():
    """When Ollama is down, summarizer returns a stats-based fallback."""
    mock_es = AsyncMock()
    mock_es.search = AsyncMock(
        return_value={
            "hits": {
                "total": {"value": 3},
                "hits": [
                    {"_id": "1", "_source": {"id": "1", "timestamp": "2026-01-01T00:00:00", "severity": "high", "source": "syslog", "category": "auth", "host": "web1", "message": "Failed SSH"}},
                    {"_id": "2", "_source": {"id": "2", "timestamp": "2026-01-01T00:01:00", "severity": "low", "source": "syslog", "category": "system", "host": "web1", "message": "Cron ran"}},
                    {"_id": "3", "_source": {"id": "3", "timestamp": "2026-01-01T00:02:00", "severity": "critical", "source": "docker", "category": "application", "host": "web2", "message": "OOM"}},
                ],
            }
        }
    )

    mock_client = AsyncMock()
    mock_client.generate = AsyncMock(side_effect=OllamaError("unavailable"))

    with (
        patch("siem.ai.summarizer.get_es_client", return_value=mock_es),
        patch("siem.ai.summarizer.get_ollama_client", return_value=mock_client),
    ):
        from siem.ai.summarizer import summarize_events

        result = await summarize_events(["1", "2", "3"])

    assert "AI summary unavailable" in result
    assert "2 high/critical" in result


# ── Explainer ──


async def test_auto_explain_ollama_down():
    """When Ollama is unavailable, auto_explain returns None."""
    mock_client = AsyncMock()
    mock_client.is_available = AsyncMock(return_value=False)

    with patch("siem.ai.explainer.get_ollama_client", return_value=mock_client):
        from siem.ai.explainer import auto_explain_alert
        from siem.models.alert import Alert
        from siem.models.event import EventSeverity

        alert = Alert(
            rule_id="test",
            rule_name="Test Rule",
            severity=EventSeverity.HIGH,
            description="Test alert",
        )
        result = await auto_explain_alert(alert)
        assert result is None
