from datetime import UTC, datetime

from siem.storage.indices import get_alert_index, get_event_index


def test_event_index_is_daily():
    when = datetime(2026, 9, 17, 14, 30, tzinfo=UTC)
    assert get_event_index(when) == "siem-events-2026.09.17"


def test_event_index_defaults_to_now():
    assert get_event_index().startswith("siem-events-")
    assert len(get_event_index()) == len("siem-events-2026.09.17")


def test_alert_index_stays_monthly():
    when = datetime(2026, 9, 17, tzinfo=UTC)
    assert get_alert_index(when) == "siem-alerts-2026.09"
