import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from elasticsearch import AsyncElasticsearch

from config.settings import settings
from siem.detection.rule_loader import load_rules, reload_rules
from siem.models.alert import Alert
from siem.models.rule import DetectionRule, RuleCondition
from siem.models.suppression import Suppression
from siem.storage.es_client import get_es_client
from siem.storage.indices import get_alert_index

logger = structlog.get_logger()


TOP_LEVEL_FIELDS = ("source", "category", "severity", "host", "message", "tags")

# Cap on the number of terms buckets a grouped rule can breach on in one
# evaluation. Kept as a named constant so the query builder and the
# truncation check below can never drift apart.
GROUP_BY_BUCKET_SIZE = 50

# How many breaching buckets of one rule evaluation may reach the AI
# suppression fallback. That fallback loops the rule's active suppressions
# and each ai_match_suppression call is bounded at 10s, so one bucket can
# already cost far more than a detection interval; at the GROUP_BY_BUCKET_SIZE
# cap of 50 it would block the 30s loop for the rest of the day. Buckets past
# the budget still get the deterministic field match, which is the path that
# actually resolves the common cases -- they just do not get the AI opinion
# on this pass, and the next pass reconsiders them from scratch.
AI_SUPPRESSION_BUCKET_BUDGET = 3


class AiSuppressionBudget:
    """One allowance of AI suppression-matcher calls, and how to spend it.

    The mechanism, in one place, for every caller that raises alerts:
    DetectionEngine takes a fresh one per rule evaluation, new_client.py
    per pass. Both hand `spend` to check_suppressions as spend_ai_budget.
    """

    def __init__(self, budget: int = AI_SUPPRESSION_BUCKET_BUDGET):
        self.budget = budget
        self.remaining = budget

    def spend(self, rule_id: str) -> bool:
        """Take one unit, or report that there is none left."""
        if self.remaining <= 0:
            logger.warning(
                "suppression_ai_budget_exhausted",
                rule_id=rule_id,
                budget=self.budget,
            )
            return False
        self.remaining -= 1
        return True


def _resolve_field(name: str) -> str:
    """Map a rule's field name to its Elasticsearch path."""
    if "." in name or name in TOP_LEVEL_FIELDS:
        return name
    return f"parsed.{name}"


def _condition_to_es_clause(cond: RuleCondition) -> dict[str, Any]:
    """Translate a RuleCondition to an Elasticsearch query clause."""
    field = _resolve_field(cond.field)

    match cond.operator:
        case "eq":
            return {"term": {field: cond.value}}
        case "contains":
            # Deliberately an OR over the value's terms: ES `match` defaults
            # to operator "or". Existing rules rely on it with single-token
            # values ("REJECT", "conntrack"), where it reads as substring
            # matching. For a multi-word value use "phrase" -- `contains`
            # with one would fire on any document containing any one word.
            return {"match": {field: cond.value}}
        case "phrase":
            # The whole value, in order, as written. This is what a
            # multi-word "contains" looks like to someone reading the rule.
            return {"match_phrase": {field: cond.value}}
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
            # Unreachable for a rule that came through RuleCondition, which
            # rejects anything outside RuleOperator. Defence in depth for
            # the paths that do not (model_construct, a future operator
            # added to the Literal and forgotten here): match nothing.
            # Returning None dropped the clause, and a dropped clause makes
            # a rule *broader*. A broken rule must never be more permissive
            # than a working one.
            logger.warning("unknown_condition_operator", operator=cond.operator)
            return {"match_none": {}}


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
        # No `if clause:` guard. Dropping a clause silently widens the
        # rule; every operator now yields a clause, including the
        # fail-closed one for an operator we do not recognise.
        must.append(_condition_to_es_clause(cond))

    # Time window
    time_from = (datetime.now(UTC) - timedelta(seconds=rule.window_seconds)).isoformat()
    must.append({"range": {"timestamp": {"gte": time_from}}})

    query: dict[str, Any] = {
        "query": {"bool": {"must": must}},
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    if rule.group_by:
        query["aggs"] = {
            "groups": {
                "terms": {
                    "field": _resolve_field(rule.group_by),
                    "size": GROUP_BY_BUCKET_SIZE,
                    "min_doc_count": rule.threshold,
                }
            }
        }

    return query


def grouped_breaches(response: dict[str, Any], threshold: int) -> list[tuple[Any, int]]:
    """Buckets that met the threshold, as (key, count), highest first.

    Prefers ``key_as_string`` over the raw ``key`` so boolean/date terms
    (which ES returns as ``0``/``1`` or epoch millis) come back in their
    human form instead of a form that silently fails to match hits later.
    """
    buckets = (
        response.get("aggregations", {}).get("groups", {}).get("buckets", [])
    )
    return [
        (b.get("key_as_string", b["key"]), b["doc_count"])
        for b in buckets
        if b["doc_count"] >= threshold
    ]


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
        self._last_reload: datetime = datetime.min.replace(tzinfo=UTC)
        self._last_expiry_check: datetime = datetime.min.replace(tzinfo=UTC)
        # Reset per rule evaluation; see AI_SUPPRESSION_BUCKET_BUDGET.
        self._ai_suppression_budget = AiSuppressionBudget()

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

                await self._expire_suppressions()
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
        # One budget per rule per pass, spent by _check_suppressions below.
        self._ai_suppression_budget = AiSuppressionBudget()
        query = build_rule_query(rule)
        result = await es.search(index="siem-events-*", body=query)
        hits = result["hits"]["hits"]
        total = result["hits"]["total"]["value"]

        # A grouped rule thresholds per bucket and raises one alert each.
        if rule.group_by:
            agg_buckets = (
                result.get("aggregations", {}).get("groups", {}).get("buckets", [])
            )
            if len(agg_buckets) >= GROUP_BY_BUCKET_SIZE:
                logger.warning(
                    "grouped_rule_bucket_cap_reached",
                    rule_id=rule.id,
                    group_by=rule.group_by,
                    bucket_cap=GROUP_BY_BUCKET_SIZE,
                )

            for key, count in grouped_breaches(result, rule.threshold):
                # Exact match, matching the re-query's exact `term` filter
                # below — ES keyword buckets are case-sensitive ("Host-A"
                # and "host-a" are distinct buckets), so this must not
                # case-fold or two case-variant buckets would share hits.
                # A boolean group_by field (key_as_string vs Python True)
                # simply misses here and falls through to the re-query,
                # which resolves it correctly.
                bucket_hits = [
                    h for h in hits
                    if str(self._hit_field(h, rule.group_by)) == str(key)
                ]
                if not bucket_hits:
                    # The window's top-100-by-recency page didn't include this
                    # bucket's own events (common once a client's doc_count
                    # exceeds 100, or when the local filter above can't match
                    # e.g. a boolean group_by field). Re-query narrowed to
                    # this bucket rather than attach another client's events
                    # as evidence.
                    bucket_hits = await self._fetch_bucket_hits(es, rule, key)
                await self._raise_alert(es, rule, bucket_hits, str(key), count)
            return

        if total < rule.threshold:
            return

        await self._raise_alert(es, rule, hits, self._extract_group_key(hits), total)

    async def _fetch_bucket_hits(
        self, es: AsyncElasticsearch, rule: DetectionRule, key: Any
    ) -> list[dict]:
        """Re-query a grouped rule narrowed to one bucket's own events.

        Used when the rule's normal (unfiltered) page of hits didn't happen
        to contain any events for a breaching bucket. Bounded to a single
        extra search and never lets a failure escape to the caller — an
        alert with no evidence is preferable to one with wrong evidence,
        but a failed re-query must not abort evaluation of other buckets
        or other rules.
        """
        try:
            query = build_rule_query(rule)
            query.pop("aggs", None)
            query["query"]["bool"]["must"].append(
                {"term": {_resolve_field(rule.group_by): key}}
            )
            result = await es.search(index="siem-events-*", body=query)
            return result["hits"]["hits"]
        except Exception:
            logger.exception(
                "bucket_requery_failed", rule_id=rule.id, group_key=str(key)
            )
            return []

    async def _raise_alert(
        self,
        es: AsyncElasticsearch,
        rule: DetectionRule,
        hits: list[dict],
        group_key: str,
        match_count: int,
    ) -> None:
        """Create an alert for one rule breach, honouring cooldown and suppression."""
        cooldown_key = f"{rule.id}:{group_key}"

        # Check cooldown
        cooldown_minutes = settings.detection_cooldown_minutes
        if cooldown_key in self._cooldowns:
            elapsed = (datetime.now(UTC) - self._cooldowns[cooldown_key]).total_seconds()
            if elapsed < cooldown_minutes * 60:
                return

        # Build context and check suppressions
        event_ids = [hit["_id"] for hit in hits[:50]]
        context = self._build_alert_context(hits)

        suppression_msg = await self._check_suppressions(rule, context, es)
        if suppression_msg:
            # Create auto-resolved alert
            alert = Alert(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                description=(
                    f"{rule.description} "
                    f"({match_count} events in {rule.window_seconds}s window)"
                ),
                matched_events=event_ids,
                context=context,
                status="resolved",
                resolution_reason=suppression_msg,
                ai_explanation=suppression_msg,
            )
            await es.index(
                index=get_alert_index(),
                id=alert.id,
                document=alert.to_es_doc(),
            )
            self._cooldowns[cooldown_key] = datetime.now(UTC)
            logger.info(
                "alert_suppressed",
                alert_id=alert.id,
                rule_id=rule.id,
                msg=suppression_msg,
            )
            return

        # Create normal alert
        alert = Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            description=(
                f"{rule.description} "
                f"({match_count} events in {rule.window_seconds}s window)"
            ),
            matched_events=event_ids,
            context=context,
        )

        # Auto-explain with AI (best-effort)
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
            matched_events=match_count,
            group_key=group_key,
        )

    @staticmethod
    def _hit_field(hit: dict, name: str):
        """Read a rule's field from a hit, resolving bare names under parsed."""
        source = hit.get("_source", {})
        if "." in name:
            cur = source
            for part in name.split("."):
                cur = (cur or {}).get(part)
            return cur
        if name in TOP_LEVEL_FIELDS:
            return source.get(name)
        return source.get("parsed", {}).get(name)

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

    async def _expire_suppressions(self) -> None:
        """Mark expired suppressions. Runs at most once per minute."""
        now = datetime.now(UTC)
        if (now - self._last_expiry_check).total_seconds() < 60:
            return
        self._last_expiry_check = now

        try:
            es = await get_es_client()
            result = await es.search(
                index="siem-suppressions",
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"status": "active"}},
                                {"range": {"expires_at": {"lt": now.isoformat()}}},
                            ]
                        }
                    },
                    "size": 100,
                },
            )
            for hit in result["hits"]["hits"]:
                await es.update(
                    index=hit["_index"],
                    id=hit["_id"],
                    body={"doc": {"status": "expired"}},
                )
            if result["hits"]["hits"]:
                logger.info("suppressions_expired", count=len(result["hits"]["hits"]))
        except Exception:
            pass  # Index may not exist yet

    async def _check_suppressions(
        self, rule: DetectionRule, context: dict, es: AsyncElasticsearch | None = None
    ) -> str | None:
        """Check whether a suppression matches this rule+context.

        Thin wrapper over the module-level check_suppressions, carrying this
        rule evaluation's AI budget. new_client.py raises alerts of its own
        and calls the same function directly.
        """
        return await check_suppressions(
            rule.id,
            rule.name,
            rule.description,
            context,
            spend_ai_budget=self._ai_suppression_budget.spend,
            es=es,
        )

    def _cleanup_cooldowns(self) -> None:
        """Remove expired cooldown entries."""
        cutoff = datetime.now(UTC) - timedelta(minutes=settings.detection_cooldown_minutes * 2)
        expired = [k for k, v in self._cooldowns.items() if v < cutoff]
        for k in expired:
            del self._cooldowns[k]


async def check_suppressions(
    rule_id: str,
    rule_name: str,
    rule_description: str,
    context: dict,
    spend_ai_budget: Callable[[str], bool] | None = None,
    es: AsyncElasticsearch | None = None,
) -> str | None:
    """Check whether an active suppression matches this rule+context.

    Returns a suppression message if suppressed, None otherwise.
    Step 1: deterministic field match. Step 2: AI fallback.

    Module-level rather than a DetectionEngine method because the engine is
    not the only thing that raises alerts -- new_client.py writes its own --
    and an alert-writing path that skips this makes the Suppressions tab
    report success for a rule it will never act on.
    """
    try:
        if es is None:
            es = await get_es_client()
        result = await es.search(
            index="siem-suppressions",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"rule_id": rule_id}},
                            {"term": {"status": "active"}},
                        ],
                        "should": [
                            {"bool": {"must_not": {"exists": {"field": "expires_at"}}}},
                            {"range": {"expires_at": {"gt": datetime.now(UTC).isoformat()}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": 20,
            },
        )
    except Exception:
        return None  # Index may not exist yet

    hits = result["hits"]["hits"]
    if not hits:
        return None

    suppressions = [Suppression.from_es_hit(h) for h in hits]

    # Step 1: Deterministic match
    for s in suppressions:
        if s.matches_context(context):
            logger.info("suppression_deterministic_match", suppression_id=s.id, rule_id=rule_id)
            return f"Auto-suppressed: {s.reason} (suppression {s.id})"

    # Step 2: AI fallback, but only while the caller still has budget for
    # it. Every alert-raising caller passes an AiSuppressionBudget.spend:
    # the engine one per rule evaluation, new_client.py one per pass.
    if spend_ai_budget is not None and not spend_ai_budget(rule_id):
        return None

    try:
        from siem.ai.suppression_matcher import ai_match_suppression

        for s in suppressions:
            matched = await ai_match_suppression(
                suppression=s,
                alert_context=context,
                alert_rule_name=rule_name,
                alert_description=rule_description,
            )
            if matched:
                logger.info("suppression_ai_match", suppression_id=s.id, rule_id=rule_id)
                return f"AI-matched suppression: {s.reason} (suppression {s.id})"
    except Exception:
        logger.debug("suppression_ai_fallback_error", rule_id=rule_id)

    return None
