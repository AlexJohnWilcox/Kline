import json

import structlog

from siem.ai.client import OllamaError, get_ollama_client
from siem.models.alert import Alert
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

SYSTEM_PROMPT = (
    "You are a security analyst explaining a SIEM alert. "
    "Be concise (3-5 sentences). Explain what happened, why it matters, "
    "and what to investigate next."
)


def _format_event(source: dict) -> str:
    ts = source.get("timestamp", "?")
    sev = source.get("severity", "?")
    src = source.get("source", "?")
    cat = source.get("category", "?")
    host = source.get("host", "?")
    msg = source.get("message", "")[:200]
    return f"[{ts}] {sev} {src}/{cat} on {host}: {msg}"


async def explain_alert(alert_id: str) -> str:
    """Generate an AI explanation for an alert and store it."""
    es = await get_es_client()
    client = get_ollama_client()

    # Fetch alert
    result = await es.search(
        index="siem-alerts-*",
        body={"query": {"term": {"id": alert_id}}, "size": 1},
    )
    hits = result["hits"]["hits"]
    if not hits:
        return "Alert not found."

    hit = hits[0]
    alert = Alert.from_es_hit(hit)

    # Fetch matched events (up to 20)
    event_lines = []
    if alert.matched_events:
        ev_result = await es.search(
            index="siem-events-*",
            body={
                "query": {"terms": {"id": alert.matched_events[:20]}},
                "size": 20,
                "sort": [{"timestamp": {"order": "desc"}}],
            },
        )
        event_lines = [_format_event(h["_source"]) for h in ev_result["hits"]["hits"]]

    context_str = json.dumps(alert.context, default=str) if alert.context else "{}"
    events_str = "\n".join(event_lines) if event_lines else "(no events available)"

    prompt = (
        f"Alert: {alert.rule_name} ({alert.severity.value})\n"
        f"Description: {alert.description}\n"
        f"Time: {alert.timestamp.isoformat()}\n"
        f"Context: {context_str}\n\n"
        f"Matched events (sample of {len(event_lines)}):\n{events_str}\n\n"
        f"Explain this alert:"
    )

    explanation = await client.generate(prompt, system=SYSTEM_PROMPT)

    # Update alert in ES
    await es.update(
        index=hit["_index"],
        id=hit["_id"],
        body={"doc": {"ai_explanation": explanation}},
    )

    return explanation


async def auto_explain_alert(alert: Alert) -> str | None:
    """Auto-explain a newly created alert. Returns explanation or None if unavailable."""
    client = get_ollama_client()
    if not await client.is_available():
        return None

    # Fetch matched events
    event_lines = []
    if alert.matched_events:
        try:
            es = await get_es_client()
            ev_result = await es.search(
                index="siem-events-*",
                body={
                    "query": {"terms": {"id": alert.matched_events[:20]}},
                    "size": 20,
                    "sort": [{"timestamp": {"order": "desc"}}],
                },
            )
            event_lines = [_format_event(h["_source"]) for h in ev_result["hits"]["hits"]]
        except Exception:
            pass

    context_str = json.dumps(alert.context, default=str) if alert.context else "{}"
    events_str = "\n".join(event_lines) if event_lines else "(no events available)"

    prompt = (
        f"Alert: {alert.rule_name} ({alert.severity.value})\n"
        f"Description: {alert.description}\n"
        f"Time: {alert.timestamp.isoformat()}\n"
        f"Context: {context_str}\n\n"
        f"Matched events (sample of {len(event_lines)}):\n{events_str}\n\n"
        f"Explain this alert:"
    )

    try:
        return await client.generate(prompt, system=SYSTEM_PROMPT)
    except OllamaError:
        logger.debug("auto_explain_unavailable", alert_id=alert.id)
        return None
