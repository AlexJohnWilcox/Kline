from fastapi import APIRouter
from pydantic import BaseModel

from siem.ai.correlator import correlate_event
from siem.ai.explainer import explain_alert
from siem.ai.nl_query import natural_language_query
from siem.ai.summarizer import summarize_events
from siem.models.query import NLQueryRequest, NLQueryResponse

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


class SummarizeRequest(BaseModel):
    event_ids: list[str]


class CorrelateRequest(BaseModel):
    event_id: str
    window_minutes: int = 5


@router.post("/summarize")
async def api_summarize(req: SummarizeRequest) -> dict:
    summary = await summarize_events(req.event_ids)
    return {"summary": summary, "event_count": len(req.event_ids)}


@router.post("/query")
async def api_nl_query(req: NLQueryRequest) -> NLQueryResponse:
    return await natural_language_query(req.question)


@router.post("/explain/{alert_id}")
async def api_explain_alert(alert_id: str) -> dict:
    explanation = await explain_alert(alert_id)
    return {"explanation": explanation, "alert_id": alert_id}


@router.post("/correlate")
async def api_correlate(req: CorrelateRequest) -> dict:
    return await correlate_event(req.event_id, req.window_minutes)
