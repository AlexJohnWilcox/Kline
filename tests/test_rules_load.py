from config.settings import settings
from siem.detection.engine import build_rule_query
from siem.detection.rule_loader import load_rules


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
    and silently never fire. Only fields declared keyword in
    EVENT_INDEX_TEMPLATE are safe to group on.
    """
    mapped = {"domain", "client", "query_type", "upstream", "host", "source"}
    for rule in load_rules(settings.rules_dir):
        if rule.group_by:
            bare = rule.group_by.removeprefix("parsed.")
            assert bare in mapped, f"{rule.id} groups on unmapped {rule.group_by}"


def test_dns_rules_build_valid_grouped_queries():
    rules = {r.id: r for r in load_rules(settings.rules_dir)}
    query = build_rule_query(rules["dns-blocked-spike"])
    assert query["aggs"]["groups"]["terms"]["field"] == "parsed.client"
