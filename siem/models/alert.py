from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from siem.models.event import EventSeverity


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rule_id: str
    rule_name: str
    severity: EventSeverity
    description: str
    matched_events: list[str] = []  # event IDs
    ai_explanation: str | None = None
    status: Literal["new", "acknowledged", "resolved"] = "new"
    context: dict[str, Any] = {}  # extra info (username, IPs, counts)

    def to_es_doc(self) -> dict[str, Any]:
        doc = self.model_dump()
        doc["timestamp"] = self.timestamp.isoformat()
        doc["severity"] = self.severity.value
        return doc

    @classmethod
    def from_es_hit(cls, hit: dict[str, Any]) -> "Alert":
        source = hit["_source"]
        source.setdefault("id", hit["_id"])
        return cls(**source)
