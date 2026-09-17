from datetime import UTC, datetime, timedelta

import pytest

from siem.tasks.retention import INDEX_DATE_PATTERN, index_end_date, should_delete


def test_pattern_matches_daily_events():
    m = INDEX_DATE_PATTERN.match("siem-events-2026.09.17")
    assert m is not None
    assert m.group(1) == "events"
    assert m.group(4) == "17"


def test_pattern_matches_monthly_alerts():
    m = INDEX_DATE_PATTERN.match("siem-alerts-2026.09")
    assert m is not None
    assert m.group(1) == "alerts"
    assert m.group(4) is None


def test_pattern_rejects_unrelated_index():
    assert INDEX_DATE_PATTERN.match("siem-suppressions") is None


def test_daily_index_ends_next_day():
    assert index_end_date(2026, 9, 17) == datetime(2026, 9, 18, tzinfo=UTC)


def test_monthly_index_ends_next_month():
    assert index_end_date(2026, 9, None) == datetime(2026, 10, 1, tzinfo=UTC)


def test_december_monthly_index_rolls_the_year():
    assert index_end_date(2026, 12, None) == datetime(2027, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "index_name,expected",
    [
        # now = 2026-09-17, retention 30d, cutoff = 2026-08-18
        ("siem-events-2026.08.16", True),   # 32 days old — ends 08-17, before cutoff
        ("siem-events-2026.08.17", False),  # exactly 31 days — ends 08-18, not before
        ("siem-events-2026.09.16", False),  # yesterday
        ("siem-events-2026.09.17", False),  # today
    ],
)
def test_thirty_day_window_at_a_month_boundary(index_name, expected):
    now = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
    cutoff = now - timedelta(days=30)
    assert should_delete(index_name, cutoff, cutoff) is expected


def test_the_bug_this_task_fixes():
    """A monthly August index would have survived a 30-day cutoff. Daily ones do not."""
    now = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
    cutoff = now - timedelta(days=30)
    assert should_delete("siem-events-2026.08", cutoff, cutoff) is False
    assert should_delete("siem-events-2026.08.01", cutoff, cutoff) is True


def test_alerts_use_their_own_cutoff():
    now = datetime(2026, 9, 17, tzinfo=UTC)
    event_cutoff = now - timedelta(days=30)
    alert_cutoff = now - timedelta(days=365)
    # Six months old: past the event cutoff, nowhere near the alert cutoff.
    assert should_delete("siem-alerts-2026.03", event_cutoff, alert_cutoff) is False
    assert should_delete("siem-alerts-2025.03", event_cutoff, alert_cutoff) is True
