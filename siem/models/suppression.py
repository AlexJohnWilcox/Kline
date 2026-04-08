from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


# Map suppression match_fields keys to alert context keys (which use plurals/different names)
_CONTEXT_KEY_MAP = {
    "user": "users",
    "host": "hosts",
    "source_ip": "source_ips",
}


class Suppression(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    rule_id: str
    reason: str
    match_fields: dict[str, str]
    source_alert_id: str
    status: Literal["active", "expired", "deleted"] = "active"

    def to_es_doc(self) -> dict[str, Any]:
        doc = self.model_dump()
        doc["created_at"] = self.created_at.isoformat()
        if self.expires_at:
            doc["expires_at"] = self.expires_at.isoformat()
        return doc

    @classmethod
    def from_es_hit(cls, hit: dict[str, Any]) -> "Suppression":
        source = hit["_source"]
        source.setdefault("id", hit["_id"])
        return cls(**source)

    def matches_context(self, context: dict[str, Any]) -> bool:
        """Check if all match_fields are present in an alert context dict."""
        for field, value in self.match_fields.items():
            context_key = _CONTEXT_KEY_MAP.get(field, field)
            context_value = context.get(context_key)
            if context_value is None:
                return False
            if isinstance(context_value, list):
                if value not in context_value:
                    return False
            elif context_value != value:
                return False
        return True

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(UTC) >= self.expires_at
