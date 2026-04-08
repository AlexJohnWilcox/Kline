from typing import Any

from pydantic import BaseModel


class NLQueryRequest(BaseModel):
    question: str


class NLQueryResponse(BaseModel):
    question: str
    es_query: dict[str, Any]
    total_hits: int
    events: list[dict[str, Any]]
    summary: str | None = None
