import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from elasticsearch import AsyncElasticsearch

from config.settings import settings
from siem.detection.rule_loader import load_rules, reload_rules
from siem.models.alert import Alert
from siem.models.rule import DetectionRule, RuleCondition
from siem.storage.es_client import get_es_client
from siem.storage.indices import get_alert_index

logger = structlog.get_logger()


def _condition_to_es_clause(cond: RuleCondition) -> dict[str, Any] | None:
    """Translate a RuleCondition to an Elasticsearch query clause."""
    # For parsed.* fields, use the full dot-path
    field = f"parsed.{cond.field}" if "." not in cond.field and cond.field not in (
        "source", "category", "severity", "host", "message", "tags"
    ) else cond.field

    match cond.operator:
        case "eq":
            return {"term": {field: cond.value}}
        case "contains":
            return {"match": {field: cond.value}}
        case "gt":
            return {"range": {field: {"gt": cond.value}}}
        case "lt":
            return {"range": {field: {"lt": cond.value}}}
        case "gte":
            return {"range": {field: {"gte": cond.value}}}
        case "lte":
            return {"range": {field: {"lte": cond.value}}}
        case "regex":
            return {"regexp": {field: cond.value}}
        case "exists":
            return {"exists": {"field": field}}
        case _:
            logger.warning("unknown_condition_operator", operator=cond.operator)
            return None


def build_rule_query(rule: DetectionRule) -> dict[str, Any]:
    """Build an Elasticsearch query for a detection rule."""
    must: list[dict[str, Any]] = []

    # Source/category filters
    if rule.source:
        must.append({"term": {"source": rule.source}})
    if rule.category:
        must.append({"term": {"category": rule.category}})

    # Rule conditions
    for cond in rule.conditions:
        clause = _condition_to_es_clause(cond)
        if clause:
            must.append(clause)

    # Time window
    time_from = (datetime.now(UTC) - timedelta(seconds=rule.window_seconds)).isoformat()
    must.append({"range": {"timestamp": {"gte": time_from}}})

    return {
        "query": {"bool": {"must": must}},
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
    }


class DetectionEngine:
    """Periodically evaluates detection rules against Elasticsearch events.

    Runs on an interval, builds ES queries from each rule, checks if event
    count exceeds threshold, and creates alerts. Uses an in-memory cooldown
    to avoid duplicate alerts for the same (rule_id, group_key) combination.
    """

    def __init__(self):
        self._rules: dict[str, DetectionRule] = {}
        self._cooldowns: dict[str, datetime] = {}  # "rule_id:group_key" -> last_alert_time
        self._task: asyncio.Task | None = None
        self._running = False
        self._last_reload: datetime = datetime.min

    @property
    def rules(self) -> dict[str, DetectionRule]:
        return self._rules

    async def start(self) -> None:
        """Start the detection loop."""
        self._rules = {r.id: r for r in load_rules(settings.rules_dir)}
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("detection_engine_started", rules=len(self._rules))

    async def stop(self) -> None:
        """Stop the detection loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("detection_engine_stopped")

    async def _run_loop(self) -> None:
        """Main detection loop."""
        while self._running:
            try:
                # Hot-reload rules every 60s
                now = datetime.now(UTC)
                if (now - self._last_reload).total_seconds() > 60:
                    self._rules = reload_rules(settings.rules_dir, self._rules)
                    self._last_reload = now
                    self._cleanup_cooldowns()

                await self._evaluate_all_rules()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("detection_loop_error")

            await asyncio.sleep(settings.detection_interval_seconds)

    async def _evaluate_all_rules(self) -> None:
        """Evaluate all enabled rules."""
        es = await get_es_client()
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            try:
                await self._evaluate_rule(es, rule)
            except Exception:
                logger.exception("rule_evaluation_error", rule_id=rule.id)

    async def _evaluate_rule(self, es: AsyncElasticsearch, rule: DetectionRule) -> None:
        """Evaluate a single rule against Elasticsearch."""
        query = build_rule_query(rule)
        result = await es.search(index="siem-events-*", body=query)
        hits = result["hits"]["hits"]
        total = result["hits"]["total"]["value"]

        if total < rule.threshold:
            return

        # Group key: for dedup, use the rule_id + a representative field
        # (e.g., src_ip for network rules, user for auth rules)
        group_key = self._extract_group_key(hits)
        cooldown_key = f"{rule.id}:{group_key}"

        # Check cooldown
        cooldown_minutes = settings.detection_cooldown_minutes
        if cooldown_key in self._cooldowns:
            elapsed = (datetime.now(UTC) - self._cooldowns[cooldown_key]).total_seconds()
            if elapsed < cooldown_minutes * 60:
                return

        # Create alert
        event_ids = [hit["_id"] for hit in hits[:50]]
        context = self._build_alert_context(hits)

        alert = Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            description=f"{rule.description} ({total} events in {rule.window_seconds}s window)",
            matched_events=event_ids,
            context=context,
        )

        # Auto-explain with AI (best-effort, non-blocking on failure)
        try:
            from siem.ai.explainer import auto_explain_alert

            explanation = await auto_explain_alert(alert)
            if explanation:
                alert.ai_explanation = explanation
        except Exception:
            logger.debug("ai_explain_skipped", alert_id=alert.id)

        await es.index(
            index=get_alert_index(),
            id=alert.id,
            document=alert.to_es_doc(),
        )

        self._cooldowns[cooldown_key] = datetime.now(UTC)
        logger.info(
            "alert_created",
            alert_id=alert.id,
            rule_id=rule.id,
            rule_name=rule.name,
            matched_events=total,
        )

    def _extract_group_key(self, hits: list[dict]) -> str:
        """Extract a group key from matched events for dedup."""
        if not hits:
            return "default"

        source = hits[0].get("_source", {})
        parsed = source.get("parsed", {})

        # Try common grouping fields
        for field in ("src_ip", "user", "container_name", "host"):
            if field in parsed:
                return str(parsed[field])

        # Fall back to host
        return source.get("host", "default")

    def _build_alert_context(self, hits: list[dict]) -> dict[str, Any]:
        """Build context dict summarising the matched events."""
        context: dict[str, Any] = {"event_count": len(hits)}

        # Collect unique values for key fields
        ips: set[str] = set()
        users: set[str] = set()
        hosts: set[str] = set()

        for hit in hits:
            source = hit.get("_source", {})
            parsed = source.get("parsed", {})
            if "src_ip" in parsed:
                ips.add(str(parsed["src_ip"]))
            if "user" in parsed:
                users.add(str(parsed["user"]))
            if "host" in source:
                hosts.add(source["host"])

        if ips:
            context["source_ips"] = sorted(ips)
        if users:
            context["users"] = sorted(users)
        if hosts:
            context["hosts"] = sorted(hosts)

        return context

    def _cleanup_cooldowns(self) -> None:
        """Remove expired cooldown entries."""
        cutoff = datetime.now(UTC) - timedelta(minutes=settings.detection_cooldown_minutes * 2)
        expired = [k for k, v in self._cooldowns.items() if v < cutoff]
        for k in expired:
            del self._cooldowns[k]
