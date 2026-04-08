from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Elasticsearch
    es_url: str = "http://localhost:9200"

    # Ollama
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout: float = 120.0
    ollama_temperature: float = 0.3

    # App
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "info"

    # Detection
    detection_interval_seconds: int = 30
    detection_cooldown_minutes: int = 15
    default_suppression_ttl_hours: int = 168  # 7 days

    # Retention
    event_retention_days: int = 90
    alert_retention_days: int = 365

    # Paths
    rules_dir: Path = Path("rules")
    templates_dir: Path = Path("frontend/templates")
    static_dir: Path = Path("frontend/static")


settings = Settings()
