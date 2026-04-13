from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config.settings import settings
from siem.models.event import EventSeverity
from siem.models.rule import DetectionRule

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


class RuleConditionInput(BaseModel):
    field: str
    operator: str
    value: str | int | float | bool | None = None


class RuleCreateRequest(BaseModel):
    id: str
    name: str
    description: str
    severity: EventSeverity
    enabled: bool = True
    source: str | None = None
    category: str | None = None
    conditions: list[RuleConditionInput]
    threshold: int = 1
    window_seconds: int = 300
    tags: list[str] = []


class RuleUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: EventSeverity | None = None
    enabled: bool | None = None
    source: str | None = None
    category: str | None = None
    conditions: list[RuleConditionInput] | None = None
    threshold: int | None = None
    window_seconds: int | None = None
    tags: list[str] | None = None


def _rule_path(rule_id: str) -> Path:
    """Get the file path for a rule ID. Validates the ID to prevent path traversal."""
    safe_id = rule_id.replace("/", "").replace("\\", "").replace("..", "")
    return settings.rules_dir / f"{safe_id}.yml"


def _rule_to_yaml(data: dict) -> str:
    """Convert rule dict to YAML string."""
    return yaml.dump(data, default_flow_style=False, sort_keys=False)


@router.get("")
async def list_rules() -> dict:
    from siem.main import detection_engine

    rules = detection_engine.rules
    return {
        "rules": [r.model_dump() for r in rules.values()],
        "count": len(rules),
    }


@router.get("/{rule_id}")
async def get_rule(rule_id: str) -> dict:
    from siem.main import detection_engine

    rule = detection_engine.rules.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule.model_dump()


@router.post("", status_code=201)
async def create_rule(req: RuleCreateRequest) -> dict:
    from siem.main import detection_engine

    path = _rule_path(req.id)
    if path.exists():
        raise HTTPException(status_code=409, detail="Rule with this ID already exists")

    # Validate by constructing the model
    rule = DetectionRule(**req.model_dump())

    # Write YAML file
    rule_data = req.model_dump(exclude_none=True)
    rule_data["severity"] = rule_data["severity"].value if hasattr(rule_data["severity"], "value") else rule_data["severity"]
    path.write_text(_rule_to_yaml(rule_data))

    # Hot-reload into engine
    detection_engine._rules[rule.id] = rule

    return {"status": "created", "rule": rule.model_dump()}


@router.put("/{rule_id}")
async def update_rule(rule_id: str, req: RuleUpdateRequest) -> dict:
    from siem.main import detection_engine

    path = _rule_path(rule_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rule not found")

    # Load existing
    existing = detection_engine.rules.get(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Rule not found in engine")

    # Merge updates
    updated_data = existing.model_dump()
    for field, value in req.model_dump(exclude_none=True).items():
        if field == "conditions":
            updated_data["conditions"] = [c if isinstance(c, dict) else c.model_dump() for c in value]
        else:
            updated_data["conditions"] = updated_data.get("conditions", [])
            updated_data[field] = value

    # Validate
    rule = DetectionRule(**updated_data)

    # Write YAML
    yaml_data = updated_data.copy()
    yaml_data["severity"] = yaml_data["severity"].value if hasattr(yaml_data["severity"], "value") else yaml_data["severity"]
    path.write_text(_rule_to_yaml(yaml_data))

    # Update engine
    detection_engine._rules[rule.id] = rule

    return {"status": "updated", "rule": rule.model_dump()}


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str) -> dict:
    from siem.main import detection_engine

    path = _rule_path(rule_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rule not found")

    path.unlink()
    detection_engine._rules.pop(rule_id, None)

    return {"status": "deleted", "rule_id": rule_id}
