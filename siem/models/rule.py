from typing import Any, Literal

from pydantic import BaseModel

from siem.models.event import EventSeverity

# The operators _condition_to_es_clause knows how to translate, as a closed
# set. A typo used to be accepted here and dropped there, and a dropped
# clause does not disable a rule -- it removes the only thing narrowing it,
# so a threshold-1 rule with one misspelled operator matched every event in
# its window. On a security tool a one-character mistake must not be able
# to widen a rule, so the mistake is refused at the point it is made: a
# ValidationError from the API, and a logged rule_load_error from the
# loader that leaves the previous rule in place.
RuleOperator = Literal[
    "eq", "contains", "phrase", "gt", "lt", "gte", "lte", "regex", "exists"
]


class RuleCondition(BaseModel):
    field: str  # dot-path into parsed fields, e.g. "action" or "src_ip"
    # "contains" matches ANY term of a multi-word value; "phrase" matches
    # all of them, in order.
    operator: RuleOperator
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
