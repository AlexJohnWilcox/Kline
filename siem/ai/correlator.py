import structlog

from siem.ai.client import OllamaError, get_ollama_client
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

SYSTEM_PROMPT = (
    "You are a security analyst performing event correlation. "
    "Identify cause-effect relationships, attack chains, or lateral movement patterns. "
    "Be specific and concise (3-6 sentences)."
)


def _format_event(source: dict) -> str:
    ts = source.get("timestamp", "?")
    sev = source.get("severity", "?")
    src = source.get("source", "?")
    cat = source.get("category", "?")
    host = source.get("host", "?")
    msg = source.get("message", "")[:200]
    return f"[{ts}] {sev} {src}/{cat} on {host}: {msg}"


async def correlate_event(
    event_id: str, window_minutes: int = 5
) -> dict:
    """Find related events and ask the LLM to identify causal chains."""
    es = await get_es_client()
    client = get_ollama_client()

    # Fetch the target event
    result = await es.search(
        index="siem-events-*",
        body={"query": {"term": {"id": event_id}}, "size": 1},
    )
    hits = result["hits"]["hits"]
    if not hits:
        return {"correlation": "Event not found.", "related_event_ids": [], "related_count": 0}

    source = hits[0]["_source"]
    parsed = source.get("parsed", {})
    timestamp = source.get("timestamp")

    # Build correlation query: events sharing host, src_ip, or user within time window
    should_clauses = []
    if source.get("host"):
        should_clauses.append({"term": {"host": source["host"]}})
    if parsed.get("src_ip"):
        should_clauses.append({"term": {"parsed.src_ip": parsed["src_ip"]}})
    if parsed.get("user"):
        should_clauses.append({"term": {"parsed.user": parsed["user"]}})

    if not should_clauses:
        return {
            "correlation": "No correlation keys (host, src_ip, user) found on this event.",
            "related_event_ids": [],
            "related_count": 0,
        }

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": f"{timestamp}||-{window_minutes}m",
                                "lte": f"{timestamp}||+{window_minutes}m",
                            }
                        }
                    }
                ],
                "should": should_clauses,
                "minimum_should_match": 1,
                "must_not": [{"term": {"id": event_id}}],
            }
        },
        "size": 100,
        "sort": [{"timestamp": {"order": "asc"}}],
    }

    related_result = await es.search(index="siem-events-*", body=query)
    related_hits = related_result["hits"]["hits"]

    if not related_hits:
        return {
            "correlation": "No related events found in the time window.",
            "related_event_ids": [],
            "related_count": 0,
        }

    related_ids = [h["_source"].get("id", h["_id"]) for h in related_hits]
    primary_line = _format_event(source)
    related_lines = [_format_event(h["_source"]) for h in related_hits[:50]]

    prompt = (
        f"Primary event:\n{primary_line}\n\n"
        f"Related events within +/- {window_minutes} minutes ({len(related_hits)} events):\n"
        f"{chr(10).join(related_lines)}\n\n"
        f"Identify any causal chains, attack patterns, or lateral movement:"
    )

    try:
        correlation = await client.generate(prompt, system=SYSTEM_PROMPT)
    except OllamaError:
        correlation = (
            f"AI correlation unavailable. Found {len(related_hits)} related events "
            f"within +/- {window_minutes} minutes."
        )

    return {
        "correlation": correlation,
        "related_event_ids": related_ids,
        "related_count": len(related_ids),
    }
