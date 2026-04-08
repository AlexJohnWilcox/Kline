import structlog

from siem.ai.client import OllamaError, get_ollama_client
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

SYSTEM_PROMPT = (
    "You are a security analyst summarizing log events for a SIEM dashboard. "
    "Be concise and focus on security implications."
)


def _format_event(source: dict) -> str:
    ts = source.get("timestamp", "?")
    sev = source.get("severity", "?")
    src = source.get("source", "?")
    cat = source.get("category", "?")
    host = source.get("host", "?")
    msg = source.get("message", "")[:200]
    return f"[{ts}] {sev} {src}/{cat} on {host}: {msg}"


async def summarize_events(event_ids: list[str]) -> str:
    """Summarize a batch of events using the LLM. Falls back to stats if Ollama is down."""
    es = await get_es_client()

    # Fetch events by ID (cap at 50)
    ids = event_ids[:50]
    result = await es.search(
        index="siem-events-*",
        body={"query": {"terms": {"id": ids}}, "size": 50, "sort": [{"timestamp": {"order": "desc"}}]},
    )
    hits = result["hits"]["hits"]
    if not hits:
        return "No events found for the given IDs."

    # Sort by severity priority then timestamp
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda h: (severity_order.get(h["_source"].get("severity", "low"), 3),))

    event_lines = [_format_event(h["_source"]) for h in hits]
    event_text = "\n".join(event_lines)

    prompt = (
        f"Summarize the following {len(hits)} log events in 2-4 sentences. "
        f"Highlight any security concerns, patterns, or anomalies.\n\n"
        f"Events:\n{event_text}\n\nSummary:"
    )

    try:
        client = get_ollama_client()
        return await client.generate(prompt, system=SYSTEM_PROMPT)
    except OllamaError:
        logger.warning("summarize_ollama_unavailable", event_count=len(hits))
        # Stats-based fallback
        severities = [h["_source"].get("severity", "low") for h in hits]
        high_count = sum(1 for s in severities if s in ("high", "critical"))
        sources = set(h["_source"].get("source", "?") for h in hits)
        return (
            f"AI summary unavailable. {len(hits)} events from {', '.join(sorted(sources))}. "
            f"{high_count} high/critical severity."
        )
