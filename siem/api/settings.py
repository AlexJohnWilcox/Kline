from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from config.settings import settings

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


class SettingsResponse(BaseModel):
    es_url: str
    ollama_url: str
    ollama_model: str
    ollama_timeout: float
    ollama_temperature: float
    detection_interval_seconds: int
    detection_cooldown_minutes: int
    event_retention_days: int
    alert_retention_days: int
    log_level: str


class SettingsUpdateRequest(BaseModel):
    ollama_model: str | None = None
    ollama_timeout: float | None = None
    ollama_temperature: float | None = None
    detection_interval_seconds: int | None = None
    detection_cooldown_minutes: int | None = None
    event_retention_days: int | None = None
    alert_retention_days: int | None = None
    log_level: str | None = None


@router.get("")
async def get_settings() -> SettingsResponse:
    return SettingsResponse(
        es_url=settings.es_url,
        ollama_url=settings.ollama_url,
        ollama_model=settings.ollama_model,
        ollama_timeout=settings.ollama_timeout,
        ollama_temperature=settings.ollama_temperature,
        detection_interval_seconds=settings.detection_interval_seconds,
        detection_cooldown_minutes=settings.detection_cooldown_minutes,
        event_retention_days=settings.event_retention_days,
        alert_retention_days=settings.alert_retention_days,
        log_level=settings.log_level,
    )


@router.patch("")
async def update_settings(req: SettingsUpdateRequest) -> dict:
    """Update settings in memory and persist changes to .env file."""
    updates = req.model_dump(exclude_none=True)
    if not updates:
        return {"status": "no changes"}

    # Apply to in-memory settings
    for key, value in updates.items():
        setattr(settings, key, value)

    # Persist to .env file
    env_path = Path(".env")
    env_lines: dict[str, str] = {}

    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env_lines[k.strip()] = v.strip()

    # Map settings fields to env var names
    field_to_env = {
        "ollama_model": "OLLAMA_MODEL",
        "ollama_timeout": "OLLAMA_TIMEOUT",
        "ollama_temperature": "OLLAMA_TEMPERATURE",
        "detection_interval_seconds": "DETECTION_INTERVAL_SECONDS",
        "detection_cooldown_minutes": "DETECTION_COOLDOWN_MINUTES",
        "event_retention_days": "EVENT_RETENTION_DAYS",
        "alert_retention_days": "ALERT_RETENTION_DAYS",
        "log_level": "LOG_LEVEL",
    }

    for field, value in updates.items():
        env_key = field_to_env.get(field)
        if env_key:
            env_lines[env_key] = str(value)

    # Write back
    output = "\n".join(f"{k}={v}" for k, v in env_lines.items()) + "\n"
    env_path.write_text(output)

    return {"status": "updated", "changes": updates}
