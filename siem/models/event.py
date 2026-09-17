from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EventSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    AUTH = "auth"
    NETWORK = "network"
    SYSTEM = "system"
    APPLICATION = "application"
    DNS = "dns"


class Event(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime
    source: str  # "syslog", "journald", "firewall", "docker", etc.
    host: str
    severity: EventSeverity = EventSeverity.LOW
    category: EventCategory = EventCategory.SYSTEM
    message: str
    parsed: dict[str, Any] = {}
    tags: list[str] = []
    raw: str = ""

    def to_es_doc(self) -> dict[str, Any]:
        """Convert to Elasticsearch document."""
        doc = self.model_dump()
        doc["timestamp"] = self.timestamp.isoformat()
        doc["severity"] = self.severity.value
        doc["category"] = self.category.value
        return doc

    @classmethod
    def from_es_hit(cls, hit: dict[str, Any]) -> "Event":
        """Create Event from an Elasticsearch hit."""
        source = hit["_source"]
        source.setdefault("id", hit["_id"])
        return cls(**source)
