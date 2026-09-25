from pathlib import Path

import pytest
from pydantic import ValidationError

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


def test_pihole_batch_size_out_of_range_low(monkeypatch):
    """PIHOLE_BATCH_SIZE=0 violates ge=1 constraint."""
    for name in DEFAULTED:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("PIHOLE_BATCH_SIZE", "0")
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    assert "pihole_batch_size" in str(exc_info.value)


def test_pihole_batch_size_out_of_range_high(monkeypatch):
    """PIHOLE_BATCH_SIZE=5001 violates le=5000 constraint."""
    for name in DEFAULTED:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("PIHOLE_BATCH_SIZE", "5001")
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    assert "pihole_batch_size" in str(exc_info.value)


def test_pihole_batch_size_valid_bounds(monkeypatch):
    """Valid PIHOLE_BATCH_SIZE values construct fine."""
    for name in DEFAULTED:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    # Test boundary values
    monkeypatch.setenv("PIHOLE_BATCH_SIZE", "1")
    s = Settings(_env_file=None)
    assert s.pihole_batch_size == 1

    monkeypatch.setenv("PIHOLE_BATCH_SIZE", "5000")
    s = Settings(_env_file=None)
    assert s.pihole_batch_size == 5000


def test_pihole_backfill_days_out_of_range_zero(monkeypatch):
    """PIHOLE_BACKFILL_DAYS=0 violates ge=1 constraint."""
    for name in DEFAULTED:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("PIHOLE_BACKFILL_DAYS", "0")
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    assert "pihole_backfill_days" in str(exc_info.value)


def test_pihole_backfill_days_valid(monkeypatch):
    """Valid PIHOLE_BACKFILL_DAYS values construct fine."""
    for name in DEFAULTED:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("PIHOLE_BACKFILL_DAYS", "1")
    s = Settings(_env_file=None)
    assert s.pihole_backfill_days == 1

    monkeypatch.setenv("PIHOLE_BACKFILL_DAYS", "365")
    s = Settings(_env_file=None)
    assert s.pihole_backfill_days == 365


def test_syslog_paths_defaults_to_empty_meaning_collector_defaults(declared_defaults):
    assert Settings(_env_file=None).syslog_paths == ""


def test_syslog_paths_parses_a_comma_separated_list(monkeypatch):
    monkeypatch.setenv("SYSLOG_PATHS", "/var/log/syslog,/var/log/gate.log")
    s = Settings(_env_file=None)
    assert s.syslog_path_list() == [Path("/var/log/syslog"), Path("/var/log/gate.log")]


def test_syslog_paths_tolerates_spaces_and_trailing_commas(monkeypatch):
    monkeypatch.setenv("SYSLOG_PATHS", " /a , /b , ")
    assert Settings(_env_file=None).syslog_path_list() == [Path("/a"), Path("/b")]


def test_an_empty_setting_yields_an_empty_list_not_a_path_to_nothing(monkeypatch):
    monkeypatch.setenv("SYSLOG_PATHS", "")
    assert Settings(_env_file=None).syslog_path_list() == []


def test_syslog_drop_patterns_unset_means_use_the_collectors_default(monkeypatch):
    monkeypatch.delenv("SYSLOG_DROP_PATTERNS", raising=False)
    assert Settings(_env_file=None).syslog_drop_pattern_list() is None


def test_an_explicitly_empty_drop_pattern_list_means_drop_nothing(monkeypatch):
    """`drop_patterns=... or None` collapsed [] to None, so there was no
    configuration value that turned dropping off -- the collector's own
    should_ingest(line, []) path was unreachable from config."""
    monkeypatch.setenv("SYSLOG_DROP_PATTERNS", "")
    assert Settings(_env_file=None).syslog_drop_pattern_list() == []


def test_syslog_drop_patterns_parses_a_comma_separated_list(monkeypatch):
    monkeypatch.setenv("SYSLOG_DROP_PATTERNS", r" dropbear.*10\.0\.0\.1 , noise , ")
    assert Settings(_env_file=None).syslog_drop_pattern_list() == [
        r"dropbear.*10\.0\.0\.1",
        "noise",
    ]


def test_the_collector_honours_each_of_the_three_states():
    """None, [], and a list are three different instructions."""
    from siem.collectors.syslog import DEFAULT_DROP_PATTERNS, SyslogCollector

    assert SyslogCollector(paths=[], drop_patterns=None).drop_patterns == (
        DEFAULT_DROP_PATTERNS
    )
    assert SyslogCollector(paths=[], drop_patterns=[]).drop_patterns == []
    assert SyslogCollector(paths=[], drop_patterns=["x"]).drop_patterns == ["x"]


def test_admin_credentials_have_no_default(monkeypatch):
    """The repo is public; a built-in admin credential is a published one."""
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    s = Settings(_env_file=None)
    assert s.admin_username is None
    assert s.admin_password is None
