import pytest

from config.settings import Settings

# Every name these tests assert a default for. Settings reads the process
# environment as well as .env, and on the deployment target both carry real
# values -- PIHOLE_ENABLED=true above all -- so without clearing them these
# tests assert the deployment's configuration rather than the declared
# defaults, and fail there. `_env_file=None` handles .env; delenv handles
# the environment the suite is run under.
DEFAULTED = (
    "PIHOLE_ENABLED",
    "PIHOLE_SSH_HOST",
    "PIHOLE_POLL_SECONDS",
    "PIHOLE_BATCH_SIZE",
    "PIHOLE_BACKFILL_DAYS",
    "EVENT_RETENTION_DAYS",
    "ALERT_RETENTION_DAYS",
)


@pytest.fixture
def declared_defaults(monkeypatch):
    """Settings as declared in code, with no .env and no environment."""
    for name in DEFAULTED:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    return Settings(_env_file=None)


def test_pihole_is_off_by_default(declared_defaults):
    assert declared_defaults.pihole_enabled is False


def test_pihole_defaults(declared_defaults):
    assert declared_defaults.pihole_ssh_host == "oracle"
    assert declared_defaults.pihole_poll_seconds == 30
    assert declared_defaults.pihole_batch_size == 500
    assert declared_defaults.pihole_backfill_days == 30


def test_retention_defaults_to_thirty_days(declared_defaults):
    assert declared_defaults.event_retention_days == 30
    assert declared_defaults.alert_retention_days == 365
