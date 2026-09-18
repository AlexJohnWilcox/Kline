from config.settings import settings
from siem.detection.engine import _condition_to_es_clause, build_rule_query
from siem.detection.rule_loader import load_rules
from siem.models.rule import RuleCondition
from siem.storage.indices import EVENT_INDEX_TEMPLATE


def explicitly_mapped_fields() -> set[str]:
    """Field names a terms aggregation can safely group on.

    Every property declared under `parsed` (keyword, integer, boolean, long
    — all aggregatable), plus the top-level properties declared keyword.
    `message` and `raw` are text and are correctly excluded: those are the
    ones that would throw a fielddata error.
    """
    properties = EVENT_INDEX_TEMPLATE["template"]["mappings"]["properties"]
    fields = {
        name for name, spec in properties.items()
        if spec.get("type") == "keyword"
    }
    fields |= set(properties["parsed"]["properties"])
    return fields


def test_the_allowlist_comes_from_the_index_template():
    fields = explicitly_mapped_fields()
    assert {"domain", "client", "query_type", "upstream"} <= fields  # parsed.*
    assert {"host", "source", "severity", "category"} <= fields  # top-level
    assert "message" not in fields and "raw" not in fields  # text, unsafe


def test_every_rule_file_parses():
    rules = load_rules(settings.rules_dir)
    assert len(rules) > 0


def test_rule_ids_are_unique():
    rules = load_rules(settings.rules_dir)
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"


def test_dns_rules_are_present_and_grouped():
    rules = {r.id: r for r in load_rules(settings.rules_dir)}
    for rule_id in ("dns-blocked-spike", "dns-nxdomain-burst"):
        assert rule_id in rules, f"{rule_id} missing"
        assert rules[rule_id].group_by, f"{rule_id} must group per client"


def test_every_rule_groups_on_an_explicitly_mapped_field():
    """A group_by on a dynamically-mapped string resolves to `text`.

    The terms aggregation then throws a fielddata error, which
    _evaluate_all_rules swallows — so the rule would log once per interval
    and silently never fire. Only fields declared in EVENT_INDEX_TEMPLATE
    are safe to group on, so the allowlist is read from the template rather
    than kept by hand — otherwise a legitimate `group_by: severity` or
    `category` would fail here for no reason anyone could act on.
    """
    mapped = explicitly_mapped_fields()
    for rule in load_rules(settings.rules_dir):
        if rule.group_by:
            bare = rule.group_by.removeprefix("parsed.")
            assert bare in mapped, f"{rule.id} groups on unmapped {rule.group_by}"


def test_dns_rules_build_valid_grouped_queries():
    rules = {r.id: r for r in load_rules(settings.rules_dir)}
    query = build_rule_query(rules["dns-blocked-spike"])
    assert query["aggs"]["groups"]["terms"]["field"] == "parsed.client"


def test_the_gate_rules_are_present():
    rules = {r.id: r for r in load_rules(settings.rules_dir)}
    assert "gate-egress-blocked" in rules
    assert "tunnel-rotation-failed" in rules


def test_the_gate_rules_read_the_syslog_source():
    """They arrive via rsyslog into a file the syslog collector tails."""
    rules = {r.id: r for r in load_rules(settings.rules_dir)}
    for rule_id in ("gate-egress-blocked", "tunnel-rotation-failed"):
        assert rules[rule_id].source == "syslog"


def _must_clauses(rule_id: str) -> list[dict]:
    rules = {r.id: r for r in load_rules(settings.rules_dir)}
    return build_rule_query(rules[rule_id])["query"]["bool"]["must"]


def test_the_gate_rules_build_valid_queries():
    """Assert the clauses, not just that there are some.

    Asserting `must` is truthy passes for any rule at all, including one
    whose condition translated to something that cannot match -- or, as
    here, to something that matches far too much.
    """
    egress = _must_clauses("gate-egress-blocked")
    assert {"term": {"source": "syslog"}} in egress
    assert {"match": {"message": "REJECT"}} in egress
    assert any("range" in c and "timestamp" in c["range"] for c in egress)

    tunnel = _must_clauses("tunnel-rotation-failed")
    assert {"term": {"source": "syslog"}} in tunnel
    assert any("range" in c and "timestamp" in c["range"] for c in tunnel)


def test_the_tunnel_rule_matches_the_whole_phrase_not_any_one_word():
    """`contains` maps to ES `match`, which ORs its terms. With threshold 1
    and severity high, "did not carry traffic" as a `contains` raised a HIGH
    alert on any line containing "not" -- and a router's syslog is dense
    with "not". Proven live: match returned hits on a Pi-hole line about
    "does-not-exist"; match_phrase returned none."""
    tunnel = _must_clauses("tunnel-rotation-failed")

    assert {"match_phrase": {"message": "did not carry traffic"}} in tunnel
    assert not any("match" in c for c in tunnel)


def test_contains_still_ors_its_terms_for_the_rules_that_rely_on_it():
    """Changing what `contains` means would silently alter every other
    rule, so the fix added an operator rather than redefining one."""
    clause = _condition_to_es_clause(
        RuleCondition(field="message", operator="contains", value="REJECT")
    )
    assert clause == {"match": {"message": "REJECT"}}


def test_an_unknown_operator_builds_nothing_rather_than_matching_everything():
    assert (
        _condition_to_es_clause(
            RuleCondition(field="message", operator="phrasey", value="x")
        )
        is None
    )
