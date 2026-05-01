from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class User(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    username: str
    password_hash: str
    role: Literal["admin", "user"] = "user"
    status: Literal["active", "disabled"] = "active"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_login: datetime | None = None

    def to_es_doc(self) -> dict[str, Any]:
        doc = self.model_dump()
        doc["created_at"] = self.created_at.isoformat()
        if self.last_login is not None:
            doc["last_login"] = self.last_login.isoformat()
        return doc

    @classmethod
    def from_es_hit(cls, hit: dict[str, Any]) -> "User":
        source = hit["_source"]
        source.setdefault("id", hit["_id"])
        return cls(**source)

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
