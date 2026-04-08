from typing import Any

from pydantic import BaseModel

from siem.models.event import EventSeverity


class RuleCondition(BaseModel):
    field: str  # dot-path into parsed fields, e.g. "action" or "src_ip"
    operator: str  # "eq", "contains", "gt", "lt", "regex", "exists"
    value: Any = None


class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    severity: EventSeverity
    enabled: bool = True
    source: str | None = None
    category: str | None = None
    conditions: list[RuleCondition]
    threshold: int = 1
    window_seconds: int = 300
    tags: list[str] = []
