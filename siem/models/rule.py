from typing import Any

from pydantic import BaseModel

from siem.models.event import EventSeverity


class RuleCondition(BaseModel):
    field: str  # dot-path into parsed fields, e.g. "action" or "src_ip"
    # "eq", "contains", "phrase", "gt", "lt", "gte", "lte", "regex", "exists".
    # "contains" matches ANY term of a multi-word value; "phrase" matches all
    # of them, in order.
    operator: str
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
    group_by: str | None = None  # dot-path to bucket on, e.g. "client"
    tags: list[str] = []
