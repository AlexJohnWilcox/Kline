import asyncio
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from config.settings import settings
from siem.auth import seed_admin_if_missing
from siem.collectors.docker import DockerCollector
from siem.collectors.network import NetworkCollector
from siem.collectors.pihole import PiholeCollector
from siem.collectors.syslog import SyslogCollector
from siem.detection.engine import DetectionEngine
from siem.ai.client import close_ollama_client, get_ollama_client
from siem.storage.es_client import close_es_client, get_es_client
from siem.storage.indices import setup_indices
from siem.tasks.collector_runner import CollectorRunner
from siem.tasks.retention import retention_loop

logger = structlog.get_logger()

# Global collector runner and detection engine (accessible from API routes)
collector_runner = CollectorRunner()
detection_engine = DetectionEngine()
_retention_task: asyncio.Task | None = None
_device_task: asyncio.Task | None = None

# Templates
templates = Jinja2Templates(directory=str(settings.templates_dir))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    logger.info("siem_starting")

    # Initialize Elasticsearch
    es = await get_es_client()
    await setup_indices(es)

    # Seed the admin account on first boot (idempotent).
    await seed_admin_if_missing(settings.admin_username, settings.admin_password)

    # Register and start collectors
    collector_runner.register(SyslogCollector())
    collector_runner.register(DockerCollector())
    collector_runner.register(NetworkCollector())
    if settings.pihole_enabled:
        collector_runner.register(
            PiholeCollector(
                ssh_host=settings.pihole_ssh_host,
                ssh_key=settings.pihole_ssh_key,
                poll_seconds=settings.pihole_poll_seconds,
                batch_size=settings.pihole_batch_size,
                backfill_days=settings.pihole_backfill_days,
            )
        )
    await collector_runner.start()

    # Start detection engine
    await detection_engine.start()

    # Start retention job
    global _retention_task
    _retention_task = asyncio.create_task(retention_loop())

    # Start device roster refresh loop
    global _device_task
    _device_task = asyncio.create_task(device_refresh_loop())

    # Check Ollama connectivity
    ollama = get_ollama_client()
    if await ollama.is_available():
        logger.info("ollama_connected", url=settings.ollama_url)
    else:
        logger.warning("ollama_unavailable", url=settings.ollama_url)

    logger.info("siem_ready", port=settings.app_port)

    yield

    # Shutdown
    if _retention_task:
        _retention_task.cancel()
        try:
            await _retention_task
        except asyncio.CancelledError:
            pass
    if _device_task:
        _device_task.cancel()
        try:
            await _device_task
        except asyncio.CancelledError:
            pass
    if device_resolver is not None:
        await device_resolver.aclose()
    await detection_engine.stop()
    await collector_runner.stop()
    await close_ollama_client()
    await close_es_client()
    logger.info("siem_stopped")


app = FastAPI(
    title="Kline",
    description="AI-powered SIEM for local log analysis",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")

# ── Auth middleware ──
# Runs BEFORE SessionMiddleware is wired (the decorator is inner; SessionMiddleware
# is added later so it sits outside and populates request.session first).

_AUTH_PUBLIC_PATHS = {"/login", "/api/v1/health"}
_AUTH_PUBLIC_PREFIXES = ("/static/", "/favicon", "/api/v1/auth/")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in _AUTH_PUBLIC_PATHS or path.startswith(_AUTH_PUBLIC_PREFIXES):
        return await call_next(request)
    if request.session.get("user_id"):
        return await call_next(request)

    # Unauthenticated — HTMX gets a client-side redirect, browsers get a 302,
    # anything else (curl/API clients) gets plain 401 JSON.
    if request.headers.get("hx-request"):
        resp = JSONResponse({"detail": "Not authenticated"}, status_code=401)
        resp.headers["HX-Redirect"] = "/login"
        return resp
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(url="/login", status_code=302)
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)


app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie=settings.session_cookie_name,
    max_age=settings.session_max_age_seconds,
    same_site="lax",
    https_only=settings.session_https_only,
)

# Register API routers
from siem.api.ai import router as ai_router
from siem.api.alerts import router as alerts_router
from siem.api.auth import router as auth_router
from siem.api.events import router as events_router
from siem.api.dashboard import router as dashboard_router
from siem.api.devices import device_refresh_loop, resolver as device_resolver
from siem.api.devices import router as devices_router
from siem.api.health import router as health_router
from siem.api.rules import router as rules_router
from siem.api.settings import router as settings_router
from siem.api.suppressions import router as suppressions_router

app.include_router(ai_router)
app.include_router(alerts_router)
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(dashboard_router)
app.include_router(devices_router)
app.include_router(health_router)
app.include_router(rules_router)
app.include_router(settings_router)
app.include_router(suppressions_router)


# ── Page routes (serve Jinja2 templates) ──


@app.get("/login", response_class=HTMLResponse)
async def page_login(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request, "login.html")


@app.get("/", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/events", response_class=HTMLResponse)
async def page_events(request: Request):
    return templates.TemplateResponse(request, "events.html")


@app.get("/alerts", response_class=HTMLResponse)
async def page_alerts(request: Request):
    return templates.TemplateResponse(request, "alerts.html")


@app.get("/search", response_class=HTMLResponse)
async def page_search(request: Request):
    return templates.TemplateResponse(request, "search.html")


@app.get("/rules", response_class=HTMLResponse)
async def page_rules(request: Request):
    return templates.TemplateResponse(request, "rules.html")


@app.get("/settings", response_class=HTMLResponse)
async def page_settings(request: Request):
    return templates.TemplateResponse(request, "settings.html")


# ── Collector status API ──


@app.get("/api/v1/collectors/status")
async def collectors_status() -> dict:
    return {"collectors": collector_runner.status()}


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


@app.get("/partials/collector-status", response_class=HTMLResponse)
async def partial_collector_status():
    """Return collector status as HTML for HTMX."""
    statuses = collector_runner.status()
    if not statuses:
        return '<p class="text-muted">No collectors registered</p>'

    rows = []
    for s in statuses:
        dot_class = "dot-green" if s["running"] else "dot-red"
        status_text = "Running" if s["running"] else "Stopped"
        rows.append(
            f'<div class="collector-status-row">'
            f'<span class="status-dot {dot_class}"></span>'
            f'<span class="collector-name">{s["name"]}</span>'
            f'<span class="badge badge-muted">{status_text}</span>'
            f'<span class="text-muted text-mono">{s["event_count"]:,} events</span>'
            f'</div>'
        )
    return "\n".join(rows)


@app.get("/partials/health-badges", response_class=HTMLResponse)
async def partial_health_badges():
    """Return health badge HTML for HTMX."""
    import httpx

    es_status = "unknown"
    ollama_status = "unknown"

    try:
        es = await get_es_client()
        health = await es.cluster.health()
        es_status = health["status"]
    except Exception:
        es_status = "offline"

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.ollama_url}/api/tags")
            if resp.status_code == 200:
                ollama_status = "online"
            else:
                ollama_status = "error"
    except Exception:
        ollama_status = "offline"

    es_dot = {
        "green": "dot-green",
        "yellow": "dot-yellow",
        "red": "dot-red",
        "offline": "dot-red",
    }.get(es_status, "dot-muted")
    ollama_dot = "dot-green" if ollama_status == "online" else "dot-red" if ollama_status == "error" else "dot-muted"

    return (
        f'<div id="health-badges-content" class="health-badges-row">'
        f'<span class="health-badge"><span class="status-dot {es_dot}"></span> ES: {es_status}</span>'
        f'<span class="health-badge"><span class="status-dot {ollama_dot}"></span> AI: {ollama_status}</span>'
        f'</div>'
    )
