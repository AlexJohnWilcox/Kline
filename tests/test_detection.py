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


def test_grouped_query_passes_through_an_explicit_dot_path():
    query = build_rule_query(_rule(group_by="host"))
    assert query["aggs"]["groups"]["terms"]["field"] == "host"


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


def test_grouped_breaches_excludes_buckets_under_threshold():
    response = {"aggregations": {"groups": {"buckets": [
        {"key": "a", "doc_count": 5},
    ]}}}
    assert grouped_breaches(response, threshold=20) == []


def test_grouped_breaches_on_a_response_with_no_aggregation():
    assert grouped_breaches({}, threshold=1) == []
