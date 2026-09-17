from config.settings import Settings


def test_pihole_is_off_by_default():
    s = Settings()
    assert s.pihole_enabled is False


def test_pihole_defaults():
    s = Settings()
    assert s.pihole_ssh_host == "oracle"
    assert s.pihole_poll_seconds == 30
    assert s.pihole_batch_size == 500
    assert s.pihole_backfill_days == 30


def test_retention_defaults_to_thirty_days():
    s = Settings()
    assert s.event_retention_days == 30
    assert s.alert_retention_days == 365
