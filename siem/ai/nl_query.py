import json

import structlog
from elasticsearch import ApiError

from siem.ai.client import OllamaError, get_ollama_client
from siem.models.event import Event
from siem.models.query import NLQueryResponse
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

SYSTEM_PROMPT = """\
You are an Elasticsearch query generator for a SIEM system.

The index pattern is "siem-events-*" with these fields:
- timestamp (date) — ISO 8601
- source (keyword) — "syslog", "docker", "firewall", "network"
- host (keyword) — hostname
- severity (keyword) — "low", "medium", "high", "critical"
- category (keyword) — "auth", "network", "system", "application"
- message (text) — free-text log message
- tags (keyword array)
- parsed.action (keyword) — e.g. "ssh_failed", "sudo_command", "container_start"
- parsed.user (keyword)
- parsed.src_ip (keyword)
- parsed.dst_ip (keyword)
- parsed.dst_port (long)
- parsed.container_name (keyword)
- parsed.service (keyword) — e.g. "sshd"

Generate ONLY a valid JSON Elasticsearch query body with a top-level "query" key.
Use bool queries with must/should/filter clauses as needed.
Do NOT include "from", "size", or "sort" — those are added automatically.
For time-based queries, use "now-1h", "now-24h", "now-7d" etc. in range filters on "timestamp".\
"""

SUMMARY_SYSTEM = (
    "You are a security analyst. Given search results from a SIEM, "
    "provide a concise 2-3 sentence summary answering the user's question."
)


def _validate_es_query(query: dict) -> bool:
    """Basic validation of a generated ES query."""
    if not isinstance(query, dict):
        return False
    if "query" not in query:
        return False
    # Block dangerous operations
    raw = json.dumps(query)
    for forbidden in ("_delete", "script", "update_by_query", "delete_by_query"):
        if forbidden in raw:
            return False
    return True


def _fallback_query(question: str) -> dict:
    """Safe multi_match fallback when LLM fails."""
    return {
        "query": {
            "multi_match": {
                "query": question,
                "fields": ["message", "source", "host", "parsed.*"],
            }
        }
    }


def _format_event_compact(source: dict) -> str:
    ts = source.get("timestamp", "?")
    sev = source.get("severity", "?")
    src = source.get("source", "?")
    host = source.get("host", "?")
    msg = source.get("message", "")[:150]
    return f"[{ts}] {sev} {src} {host}: {msg}"


async def natural_language_query(question: str) -> NLQueryResponse:
    """Translate a natural-language question to an ES query, execute it, and summarize."""
    client = get_ollama_client()
    es = await get_es_client()

    es_query = None
    used_fallback = False

    # Try LLM query generation (with one retry)
    for attempt in range(2):
        try:
            prompt = question if attempt == 0 else (
                f"Your previous response was not valid JSON. "
                f"Return ONLY a JSON object with a top-level \"query\" key.\n\n{question}"
            )
            raw = await client.generate(prompt, system=SYSTEM_PROMPT, json_mode=True)
            parsed = json.loads(raw)
            if _validate_es_query(parsed):
                es_query = parsed
                break
            logger.warning("nl_query_invalid", attempt=attempt, raw=raw[:200])
        except (json.JSONDecodeError, OllamaError) as e:
            logger.warning("nl_query_attempt_failed", attempt=attempt, error=str(e))

    if es_query is None:
        es_query = _fallback_query(question)
        used_fallback = True

    # Execute query — if ES rejects the LLM-generated DSL, fall back to multi_match.
    body = {**es_query, "size": 50, "sort": [{"timestamp": {"order": "desc"}}]}
    try:
        result = await es.search(index="siem-events-*", body=body)
    except ApiError as e:
        logger.warning("nl_query_es_rejected", error=str(e), query=es_query)
        es_query = _fallback_query(question)
        used_fallback = True
        body = {**es_query, "size": 50, "sort": [{"timestamp": {"order": "desc"}}]}
        result = await es.search(index="siem-events-*", body=body)
    total = result["hits"]["total"]["value"]
    hits = result["hits"]["hits"]
    events = [Event.from_es_hit(hit).model_dump() for hit in hits]

    # Serialize for JSON response (convert datetimes/enums)
    for ev in events:
        if hasattr(ev.get("timestamp"), "isoformat"):
            ev["timestamp"] = ev["timestamp"].isoformat()
        if hasattr(ev.get("severity"), "value"):
            ev["severity"] = ev["severity"].value
        if hasattr(ev.get("category"), "value"):
            ev["category"] = ev["category"].value

    # Summarize results with LLM
    summary = None
    if hits and not used_fallback:
        try:
            event_text = "\n".join(_format_event_compact(h["_source"]) for h in hits[:20])
            summary_prompt = (
                f"User question: {question}\n\n"
                f"Search returned {total} results. Top {min(len(hits), 20)}:\n{event_text}\n\n"
                f"Summarize the findings:"
            )
            summary = await client.generate(summary_prompt, system=SUMMARY_SYSTEM)
        except OllamaError:
            summary = f"Found {total} matching events."
    elif total > 0:
        summary = f"Found {total} matching events (used text search fallback)."
    else:
        summary = "No matching events found."

    return NLQueryResponse(
        question=question,
        es_query=es_query,
        total_hits=total,
        events=events,
        summary=summary,
    )
