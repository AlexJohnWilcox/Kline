from pathlib import Path

from siem.detection.engine import build_rule_query, _condition_to_es_clause
from siem.detection.rule_loader import load_rules
from siem.models.event import EventSeverity
from siem.models.rule import DetectionRule, RuleCondition


# ── Rule Loader tests ──


def test_load_rules_from_directory():
    rules = load_rules(Path("rules"))
    assert len(rules) >= 3  # at least the original 3 rules
    rule_ids = {r.id for r in rules}
    assert "brute-force-ssh" in rule_ids
    assert "unusual-outbound-dns" in rule_ids
    assert "docker-privileged" in rule_ids


def test_load_rules_includes_new_rules():
    rules = load_rules(Path("rules"))
    rule_ids = {r.id for r in rules}
    assert "sudo-escalation" in rule_ids
    assert "unusual-port" in rule_ids
    assert "high-error-rate" in rule_ids


def test_load_rules_missing_dir():
    rules = load_rules(Path("/nonexistent/path"))
    assert rules == []


def test_loaded_rule_structure():
    rules = load_rules(Path("rules"))
    ssh_rule = next(r for r in rules if r.id == "brute-force-ssh")
    assert ssh_rule.name == "SSH Brute Force Attempt"
    assert ssh_rule.severity == EventSeverity.HIGH
    assert ssh_rule.threshold == 5
    assert ssh_rule.window_seconds == 300
    assert len(ssh_rule.conditions) == 2


# ── Condition to ES clause tests ──


def test_condition_eq():
    cond = RuleCondition(field="action", operator="eq", value="failed_login")
    clause = _condition_to_es_clause(cond)
    assert clause == {"term": {"parsed.action": "failed_login"}}


def test_condition_contains():
    cond = RuleCondition(field="message", operator="contains", value="error")
    clause = _condition_to_es_clause(cond)
    assert clause == {"match": {"message": "error"}}


def test_condition_gt():
    cond = RuleCondition(field="dst_port", operator="gt", value=1024)
    clause = _condition_to_es_clause(cond)
    assert clause == {"range": {"parsed.dst_port": {"gt": 1024}}}


def test_condition_exists():
    cond = RuleCondition(field="src_ip", operator="exists")
    clause = _condition_to_es_clause(cond)
    assert clause == {"exists": {"field": "parsed.src_ip"}}


def test_condition_regex():
    cond = RuleCondition(field="user", operator="regex", value="admin.*")
    clause = _condition_to_es_clause(cond)
    assert clause == {"regexp": {"parsed.user": "admin.*"}}


def test_condition_top_level_field():
    """Top-level fields like 'source' shouldn't get parsed. prefix."""
    cond = RuleCondition(field="source", operator="eq", value="syslog")
    clause = _condition_to_es_clause(cond)
    assert clause == {"term": {"source": "syslog"}}


# ── Build Rule Query tests ──


def test_build_rule_query_basic():
    rule = DetectionRule(
        id="test",
        name="Test Rule",
        description="test",
        severity=EventSeverity.HIGH,
        source="syslog",
        category="auth",
        conditions=[
            RuleCondition(field="action", operator="eq", value="failed_login"),
        ],
        threshold=5,
        window_seconds=300,
    )
    query = build_rule_query(rule)
    must = query["query"]["bool"]["must"]

    # Should have: source term, category term, condition term, time range
    assert len(must) == 4
    assert {"term": {"source": "syslog"}} in must
    assert {"term": {"category": "auth"}} in must
    assert {"term": {"parsed.action": "failed_login"}} in must
    # Last one should be a time range
    assert any("range" in clause and "timestamp" in clause["range"] for clause in must)


def test_build_rule_query_no_source():
    rule = DetectionRule(
        id="test",
        name="Test Rule",
        description="test",
        severity=EventSeverity.HIGH,
        conditions=[
            RuleCondition(field="severity", operator="eq", value="high"),
        ],
        threshold=20,
        window_seconds=600,
    )
    query = build_rule_query(rule)
    must = query["query"]["bool"]["must"]

    # Should have: condition + time range only (no source/category)
    assert len(must) == 2


from siem.models.suppression import Suppression


def test_suppression_matches_alert_context():
    """Verify suppression matching works with the context format the engine produces."""
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing",
        match_fields={"user": "alex"},
        source_alert_id="x",
    )
    # This is the format _build_alert_context produces
    context = {"event_count": 6, "users": ["alex"], "hosts": ["myhost"]}
    assert s.matches_context(context) is True

    context_miss = {"event_count": 6, "users": ["bob"], "hosts": ["myhost"]}
    assert s.matches_context(context_miss) is False


from siem.detection.engine import grouped_breaches


def _rule(**kw):
    base = {
        "id": "r", "name": "R", "description": "d", "severity": "medium",
        "conditions": [RuleCondition(field="blocked", operator="eq", value=True)],
        "threshold": 20, "window_seconds": 300,
    }
    base.update(kw)
    return DetectionRule(**base)


def test_group_by_defaults_to_none():
    assert _rule().group_by is None


def test_ungrouped_query_has_no_aggregation():
    assert "aggs" not in build_rule_query(_rule())


def test_grouped_query_aggregates_on_the_keyword_field():
    query = build_rule_query(_rule(group_by="client"))
    terms = query["aggs"]["groups"]["terms"]
    assert terms["field"] == "parsed.client"
    assert terms["min_doc_count"] == 20
    assert terms["size"] == 50


def test_grouped_query_passes_through_an_explicit_dot_path():
    # "host" is a TOP_LEVEL_FIELDS name, not a dot path, and would pass
    # through _resolve_field unchanged either way — use a real dot path
    # so this test actually exercises the dotted branch.
    query = build_rule_query(_rule(group_by="parsed.client"))
    assert query["aggs"]["groups"]["terms"]["field"] == "parsed.client"


def test_grouped_breaches_returns_buckets_over_threshold():
    response = {
        "aggregations": {
            "groups": {
                "buckets": [
                    {"key": "192.168.10.241", "doc_count": 55},
                    {"key": "192.168.10.203", "doc_count": 21},
                ]
            }
        }
    }
    assert grouped_breaches(response, threshold=20) == [
        ("192.168.10.241", 55),
        ("192.168.10.203", 21),
    ]


def test_grouped_breaches_includes_bucket_at_exact_threshold():
    """`>=` is the semantics of "met the threshold" — a bucket with
    doc_count exactly equal to the threshold must not be dropped."""
    response = {"aggregations": {"groups": {"buckets": [
        {"key": "a", "doc_count": 20},
    ]}}}
    assert grouped_breaches(response, threshold=20) == [("a", 20)]


def test_grouped_breaches_excludes_buckets_under_threshold():
    response = {"aggregations": {"groups": {"buckets": [
        {"key": "a", "doc_count": 5},
    ]}}}
    assert grouped_breaches(response, threshold=20) == []


def test_grouped_breaches_on_a_response_with_no_aggregation():
    assert grouped_breaches({}, threshold=1) == []


def test_grouped_breaches_prefers_key_as_string():
    """Boolean/date terms come back as key: 0/1 with the human form in
    key_as_string; prefer the human form so later string matching against
    hit field values (e.g. str(True)) has a chance of succeeding."""
    response = {"aggregations": {"groups": {"buckets": [
        {"key": 1, "key_as_string": "true", "doc_count": 25},
    ]}}}
    assert grouped_breaches(response, threshold=20) == [("true", 25)]


# ── _evaluate_rule / _raise_alert split ──

from unittest.mock import AsyncMock

from siem.detection.engine import DetectionEngine


async def test_evaluate_rule_ungrouped_calls_raise_alert_once_with_total():
    """The ungrouped path must still call _raise_alert with the group key
    from _extract_group_key and the total hit count, unchanged."""
    engine = DetectionEngine()
    engine._raise_alert = AsyncMock()
    rule = _rule(group_by=None, threshold=2)
    hits = [
        {"_id": "1", "_source": {"host": "h1", "parsed": {"blocked": True}}},
        {"_id": "2", "_source": {"host": "h1", "parsed": {"blocked": True}}},
    ]
    mock_es = AsyncMock()
    mock_es.search = AsyncMock(
        return_value={"hits": {"total": {"value": 2}, "hits": hits}}
    )

    await engine._evaluate_rule(mock_es, rule)

    engine._raise_alert.assert_awaited_once_with(
        mock_es, rule, hits, engine._extract_group_key(hits), 2
    )


async def test_evaluate_rule_ungrouped_below_threshold_skips_raise_alert():
    engine = DetectionEngine()
    engine._raise_alert = AsyncMock()
    rule = _rule(group_by=None, threshold=5)
    mock_es = AsyncMock()
    mock_es.search = AsyncMock(
        return_value={"hits": {"total": {"value": 2}, "hits": []}}
    )

    await engine._evaluate_rule(mock_es, rule)

    engine._raise_alert.assert_not_awaited()


async def test_evaluate_rule_grouped_calls_raise_alert_per_bucket():
    """A grouped rule must call _raise_alert once per breaching bucket,
    each with that bucket's own key and count, filtered to that bucket's
    own hits."""
    engine = DetectionEngine()
    engine._raise_alert = AsyncMock()
    rule = _rule(group_by="client", threshold=20)
    hit_a = {"_id": "a1", "_source": {"host": "h1", "parsed": {
        "client": "192.168.10.241", "blocked": True,
    }}}
    hit_b = {"_id": "b1", "_source": {"host": "h1", "parsed": {
        "client": "192.168.10.203", "blocked": True,
    }}}
    mock_es = AsyncMock()
    mock_es.search = AsyncMock(
        return_value={
            "hits": {"total": {"value": 76}, "hits": [hit_a, hit_b]},
            "aggregations": {"groups": {"buckets": [
                {"key": "192.168.10.241", "doc_count": 55},
                {"key": "192.168.10.203", "doc_count": 21},
            ]}},
        }
    )

    await engine._evaluate_rule(mock_es, rule)

    assert engine._raise_alert.await_count == 2
    engine._raise_alert.assert_any_await(
        mock_es, rule, [hit_a], "192.168.10.241", 55
    )
    engine._raise_alert.assert_any_await(
        mock_es, rule, [hit_b], "192.168.10.203", 21
    )
    # Only one search call was needed — both buckets' hits were already
    # on the page.
    assert mock_es.search.await_count == 1


async def test_evaluate_rule_grouped_requeries_instead_of_borrowing_foreign_hits():
    """If a breaching bucket's own events aren't on the window's recency-
    sorted page (common once a client's doc_count exceeds the page size),
    the engine must re-query narrowed to that bucket rather than raise an
    alert using another client's hits as evidence."""
    engine = DetectionEngine()
    engine._raise_alert = AsyncMock()
    rule = _rule(group_by="client", threshold=20)

    # The unfiltered page is entirely client B's traffic; client A breached
    # with 5000 events but none of A's events made the top-100-by-recency
    # page.
    foreign_hit = {"_id": "b1", "_source": {"host": "h1", "parsed": {
        "client": "192.168.10.203", "blocked": True,
    }}}
    own_hit = {"_id": "a1", "_source": {"host": "h1", "parsed": {
        "client": "192.168.10.241", "blocked": True,
    }}}

    mock_es = AsyncMock()
    mock_es.search = AsyncMock(side_effect=[
        {
            "hits": {"total": {"value": 5100}, "hits": [foreign_hit]},
            "aggregations": {"groups": {"buckets": [
                {"key": "192.168.10.241", "doc_count": 5000},
            ]}},
        },
        {"hits": {"total": {"value": 5000}, "hits": [own_hit]}},
    ])

    await engine._evaluate_rule(mock_es, rule)

    assert mock_es.search.await_count == 2
    requery_body = mock_es.search.await_args_list[1].kwargs["body"]
    assert {"term": {"parsed.client": "192.168.10.241"}} in (
        requery_body["query"]["bool"]["must"]
    )
    assert "aggs" not in requery_body

    engine._raise_alert.assert_awaited_once_with(
        mock_es, rule, [own_hit], "192.168.10.241", 5000
    )


async def test_evaluate_rule_grouped_requery_failure_yields_empty_hits():
    """A failed re-query must not escape _evaluate_rule — it should raise
    the alert with no evidence rather than crash evaluation."""
    engine = DetectionEngine()
    engine._raise_alert = AsyncMock()
    rule = _rule(group_by="client", threshold=20)

    mock_es = AsyncMock()
    mock_es.search = AsyncMock(side_effect=[
        {
            "hits": {"total": {"value": 5000}, "hits": []},
            "aggregations": {"groups": {"buckets": [
                {"key": "192.168.10.241", "doc_count": 5000},
            ]}},
        },
        RuntimeError("es unavailable"),
    ])

    await engine._evaluate_rule(mock_es, rule)

    engine._raise_alert.assert_awaited_once_with(
        mock_es, rule, [], "192.168.10.241", 5000
    )
