from pathlib import Path

import structlog
import yaml

from siem.models.rule import DetectionRule

logger = structlog.get_logger()


def load_rules(rules_dir: Path) -> list[DetectionRule]:
    """Load all YAML detection rules from the given directory."""
    rules: list[DetectionRule] = []
    if not rules_dir.is_dir():
        logger.warning("rules_dir_not_found", path=str(rules_dir))
        return rules

    for path in sorted(rules_dir.glob("*.yml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if data is None:
                continue
            rule = DetectionRule(**data)
            rules.append(rule)
            logger.debug("rule_loaded", rule_id=rule.id, name=rule.name)
        except Exception:
            logger.exception("rule_load_error", path=str(path))

    logger.info("rules_loaded", count=len(rules))
    return rules


def reload_rules(rules_dir: Path, existing: dict[str, DetectionRule]) -> dict[str, DetectionRule]:
    """Reload rules, returning updated mapping of rule_id -> rule.

    Preserves any rules that haven't changed, adds new ones, removes deleted ones.
    """
    fresh = load_rules(rules_dir)
    updated: dict[str, DetectionRule] = {}
    for rule in fresh:
        updated[rule.id] = rule
    return updated
