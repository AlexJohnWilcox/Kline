from pathlib import Path
from secrets import token_urlsafe

from pydantic import Field
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
    event_retention_days: int = 30
    alert_retention_days: int = 365

    # Pi-hole collector (pulls the Oracle's FTL database over SSH)
    pihole_enabled: bool = False
    pihole_ssh_host: str = "oracle"
    pihole_ssh_key: str | None = None
    pihole_poll_seconds: int = 30
    # Bounds match the Oracle reader's accept range; violation surfaces as a
    # pydantic error naming PIHOLE_BATCH_SIZE before ES client init, rather than
    # a bare ValueError partway through the FastAPI lifespan.
    pihole_batch_size: int = Field(default=500, ge=1, le=5000)
    # Backfill zero means "read from rowid 0", which the reader interprets as
    # "entire database" (~1.28 million rows). ge=1 forbids the trap.
    pihole_backfill_days: int = Field(default=30, ge=1)

    # Extra syslog files to tail, comma separated. Empty means the collector's
    # own defaults. The Gate's remote stream lands somewhere no default list
    # knows about, so it has to be named here.
    syslog_paths: str = ""

    # Device names - resolved from the sanctum's own roster at render time,
    # never written onto events. Off by default: without it every host shows
    # as its raw address, which is the behaviour this replaces.
    device_names_enabled: bool = False
    device_roster_url: str = "https://dash.lan/data.json"
    # Path to the CA that signed the roster URL. Effectively required for a
    # privately signed roster (dash.lan is signed by Caddy's internal root):
    # httpx verifies against certifi's bundle, NOT the system trust store, so
    # a host curl and the browser both accept can still fail here with
    # CERTIFICATE_VERIFY_FAILED. The dashboard publishes its root at
    # /caddy-root.crt; see .env.example for the one-line fetch. Unset means
    # "verify against certifi", which only works for a public certificate.
    device_roster_ca: str | None = None
    device_roster_refresh_seconds: int = Field(default=300, ge=30)

    # Auth
    # If SESSION_SECRET is unset, a random one is generated per process
    # (sessions invalidate on restart). Set it in .env for stable sessions.
    session_secret: str = Field(default_factory=lambda: token_urlsafe(32))
    session_cookie_name: str = "kline_session"
    session_max_age_seconds: int = 43200  # 12 hours
    session_https_only: bool = False
    # First-boot admin seed — only used if no user with this username exists.
    admin_username: str = "alexwilcox"
    admin_password: str = "REDACTED"

    # Paths
    rules_dir: Path = Path("rules")
    templates_dir: Path = Path("frontend/templates")
    static_dir: Path = Path("frontend/static")

    def syslog_path_list(self) -> list[Path]:
        """Parse syslog_paths, tolerating spaces and trailing separators."""
        return [Path(p.strip()) for p in self.syslog_paths.split(",") if p.strip()]


settings = Settings()
