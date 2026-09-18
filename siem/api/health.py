import httpx
from fastapi import APIRouter

from config.settings import settings
from siem.storage.es_client import get_es_client

router = APIRouter(tags=["health"])


@router.get("/api/v1/health")
async def health_check() -> dict:
    status = {"status": "ok", "elasticsearch": "unknown", "ollama": "unknown"}

    # Check Elasticsearch
    try:
        es = await get_es_client()
        health = await es.cluster.health()
        status["elasticsearch"] = health["status"]
    except Exception as e:
        status["elasticsearch"] = f"error: {e}"
        status["status"] = "degraded"

    # Check Ollama
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ollama_url}/api/tags")
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                status["ollama"] = "connected"
                status["ollama_models"] = models
            else:
                status["ollama"] = f"error: HTTP {resp.status_code}"
                status["status"] = "degraded"
    except Exception:
        status["ollama"] = "unavailable"
        status["status"] = "degraded"

    # Check collectors
    from siem.main import collector_runner

    collectors = collector_runner.status()
    # This endpoint is public (see _AUTH_PUBLIC_PATHS in main.py), and
    # blind_reason is built from configured paths -- "no readable paths
    # among: /var/log/syslog, /var/log/gate.log". An unauthenticated caller
    # learns the deployment's log layout and which files the service cannot
    # read. The health verdict is the part liveness checks need; the reason
    # stays on the authenticated /api/v1/collectors/status.
    status["collectors"] = [
        {k: v for k, v in c.items() if k != "blind_reason"} for c in collectors
    ]
    if any(c["health"] == "blind" for c in collectors):
        status["status"] = "degraded"

    return status


@router.get("/api/v1/collectors/status")
async def collectors_status() -> list[dict]:
    """Full collector status, blind_reason included.

    Authenticated, unlike /api/v1/health: the global auth middleware in
    main.py gates every path that is not in _AUTH_PUBLIC_PATHS, and this
    one deliberately is not. blind_reason names configured filesystem
    paths -- the detail an operator needs and an anonymous caller has no
    business reading.
    """
    from siem.main import collector_runner

    return collector_runner.status()
