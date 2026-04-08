from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from config.settings import settings
from siem.collectors.docker import DockerCollector
from siem.collectors.network import NetworkCollector
from siem.collectors.syslog import SyslogCollector
from siem.detection.engine import DetectionEngine
from siem.ai.client import close_ollama_client, get_ollama_client
from siem.storage.es_client import close_es_client, get_es_client
from siem.storage.indices import setup_indices
from siem.tasks.collector_runner import CollectorRunner

logger = structlog.get_logger()

# Global collector runner and detection engine (accessible from API routes)
collector_runner = CollectorRunner()
detection_engine = DetectionEngine()

# Templates
templates = Jinja2Templates(directory=str(settings.templates_dir))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    logger.info("siem_starting")

    # Initialize Elasticsearch
    es = await get_es_client()
    await setup_indices(es)

    # Register and start collectors
    collector_runner.register(SyslogCollector())
    collector_runner.register(DockerCollector())
    collector_runner.register(NetworkCollector())
    await collector_runner.start()

    # Start detection engine
    await detection_engine.start()

    # Check Ollama connectivity
    ollama = get_ollama_client()
    if await ollama.is_available():
        logger.info("ollama_connected", url=settings.ollama_url)
    else:
        logger.warning("ollama_unavailable", url=settings.ollama_url)

    logger.info("siem_ready", port=settings.app_port)

    yield

    # Shutdown
    await detection_engine.stop()
    await collector_runner.stop()
    await close_ollama_client()
    await close_es_client()
    logger.info("siem_stopped")


app = FastAPI(
    title="SIEM",
    description="Local SIEM with AI-powered log analysis",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")

# Register API routers
from siem.api.ai import router as ai_router
from siem.api.alerts import router as alerts_router
from siem.api.events import router as events_router
from siem.api.dashboard import router as dashboard_router
from siem.api.health import router as health_router

app.include_router(ai_router)
app.include_router(alerts_router)
app.include_router(events_router)
app.include_router(dashboard_router)
app.include_router(health_router)


# ── Rules API (reads from detection engine) ──


@app.get("/api/v1/rules")
async def list_rules() -> dict:
    rules = detection_engine.rules
    return {
        "rules": [r.model_dump() for r in rules.values()],
        "count": len(rules),
    }


# ── Page routes (serve Jinja2 templates) ──


@app.get("/", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/events", response_class=HTMLResponse)
async def page_events(request: Request):
    return templates.TemplateResponse("events.html", {"request": request})


@app.get("/alerts", response_class=HTMLResponse)
async def page_alerts(request: Request):
    return templates.TemplateResponse("alerts.html", {"request": request})


@app.get("/search", response_class=HTMLResponse)
async def page_search(request: Request):
    return templates.TemplateResponse("search.html", {"request": request})


@app.get("/rules", response_class=HTMLResponse)
async def page_rules(request: Request):
    return templates.TemplateResponse("rules.html", {"request": request})


# ── HTMX partials ──


@app.get("/partials/recent-events", response_class=HTMLResponse)
async def partial_recent_events():
    """Return recent events as HTML table rows for HTMX."""
    try:
        from siem.storage.queries import search_events

        es = await get_es_client()
        events, _ = await search_events(es, page=1, size=10)

        if not events:
            return '<tr><td colspan="4" class="text-muted">No events yet</td></tr>'

        rows = []
        for e in events:
            ts = e.timestamp.strftime("%H:%M:%S") if hasattr(e.timestamp, "strftime") else str(e.timestamp)
            sev_class = f"badge-{e.severity.value}"
            msg = e.message[:80] + "..." if len(e.message) > 80 else e.message
            rows.append(
                f"<tr>"
                f'<td class="text-mono">{ts}</td>'
                f'<td><span class="badge badge-info">{e.source}</span></td>'
                f'<td><span class="badge {sev_class}">{e.severity.value}</span></td>'
                f'<td class="truncate">{msg}</td>'
                f"</tr>"
            )
        return "\n".join(rows)
    except Exception as exc:
        logger.warning("partial_recent_events_error", error=str(exc))
        return '<tr><td colspan="4" class="text-muted">Unable to load events</td></tr>'


@app.get("/partials/health-badges", response_class=HTMLResponse)
async def partial_health_badges():
    """Return health badge HTML for HTMX."""
    import httpx

    es_status = "unknown"
    es_class = "badge-muted"
    ollama_status = "unknown"
    ollama_class = "badge-muted"

    try:
        es = await get_es_client()
        health = await es.cluster.health()
        es_status = health["status"]
        es_class = {
            "green": "badge-success",
            "yellow": "badge-warning",
            "red": "badge-danger",
        }.get(es_status, "badge-muted")
    except Exception:
        es_status = "offline"
        es_class = "badge-danger"

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.ollama_url}/api/tags")
            if resp.status_code == 200:
                ollama_status = "online"
                ollama_class = "badge-success"
            else:
                ollama_status = "error"
                ollama_class = "badge-danger"
    except Exception:
        ollama_status = "offline"
        ollama_class = "badge-muted"

    return (
        f'<div id="health-badges-content">'
        f'<span class="badge {es_class}">ES: {es_status}</span> '
        f'<span class="badge {ollama_class}">AI: {ollama_status}</span>'
        f'</div>'
    )
