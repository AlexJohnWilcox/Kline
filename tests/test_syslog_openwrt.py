"""OpenWrt logread's raw boot-time replay format.

Unlike the live feed (rewritten by the receiving syslog daemon into standard
BSD or ISO timestamps before it hits disk), a boot-time replay appends the
router's raw `logread` lines directly:

    Thu Sep 18 03:11:50 2026 daemon.notice rotate-road: message

Four-digit year, leading weekday, and a facility.level field where BSD
syslog would put a hostname. Before this format was added, every one of
these lines returned None from parse_syslog_line and was silently dropped.
"""

from siem.collectors.syslog import parse_syslog_line
from siem.models.event import EventCategory, EventSeverity

ROAD_ROTATION = (
    "Thu Sep 18 03:11:50 2026 daemon.notice rotate-road: "
    "FAIL US-VA did not carry traffic within 20s; rolling back"
)
DROPBEAR_PUBKEY = (
    "Thu Sep 17 09:06:57 2026 authpriv.notice dropbear[19781]: "
    "Pubkey auth succeeded for 'root' from 192.168.10.203:37442"
)
DROPBEAR_EXIT = (
    "Thu Sep 17 07:56:30 2026 authpriv.info dropbear[14976]: "
    "Exit (root) from <192.168.10.2:39248>: Disconnect received"
)


def test_road_rotation_failure_is_parsed():
    event = parse_syslog_line(ROAD_ROTATION)
    assert event is not None
    assert event.source == "syslog"
    assert event.host == "gate"
    assert event.category == EventCategory.SYSTEM
    assert event.parsed["process"] == "rotate-road"
    assert "pid" not in event.parsed
    assert event.parsed["facility"] == "daemon.notice"
    assert "did not carry traffic" in event.message


def test_dropbear_line_with_bracketed_pid_is_parsed():
    event = parse_syslog_line(DROPBEAR_PUBKEY)
    assert event is not None
    assert event.host == "gate"
    assert event.parsed["process"] == "dropbear"
    assert event.parsed["pid"] == 19781
    assert event.parsed["facility"] == "authpriv.notice"


def test_second_dropbear_line_is_also_parsed():
    event = parse_syslog_line(DROPBEAR_EXIT)
    assert event is not None
    assert event.host == "gate"
    assert event.parsed["pid"] == 14976
    assert event.parsed["facility"] == "authpriv.info"


def test_openwrt_timestamp_uses_its_own_four_digit_year():
    event = parse_syslog_line(ROAD_ROTATION)
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 9
    assert event.timestamp.day == 18
    assert event.timestamp.hour == 3
    assert event.timestamp.minute == 11
    assert event.timestamp.second == 50


def test_err_level_escalates_severity_even_without_a_fail_keyword():
    line = "Thu Sep 18 04:00:00 2026 daemon.err watchdog: timer reset unexpectedly"
    event = parse_syslog_line(line)
    assert event is not None
    assert event.severity == EventSeverity.HIGH


def test_crit_level_escalates_severity_to_critical():
    line = "Thu Sep 18 04:00:00 2026 kern.crit kernel: watchdog reboot imminent"
    event = parse_syslog_line(line)
    assert event is not None
    assert event.severity == EventSeverity.CRITICAL


def test_message_level_failure_still_drives_severity_up():
    """rotate-road logs its own failures at .notice; the message text
    ("FAIL ... did not carry traffic") still has to push severity to
    MEDIUM even though the facility level alone only implies LOW."""
    event = parse_syslog_line(ROAD_ROTATION)
    assert event.severity == EventSeverity.MEDIUM


def test_unparseable_openwrt_shaped_line_returns_none_not_raises():
    # No dot between facility and level: none of the three patterns match.
    line = "Thu Sep 18 03:11:50 2026 daemonnotice rotate-road: FAIL"
    assert parse_syslog_line(line) is None


def test_existing_bsd_format_still_parses():
    line = (
        "Mar 22 10:15:32 myhost sshd[1234]: "
        "Failed password for root from 10.0.0.5 port 4444 ssh2"
    )
    event = parse_syslog_line(line)
    assert event is not None
    assert event.host == "myhost"
    assert event.parsed["action"] == "failed_login"


def test_existing_iso_format_still_parses():
    line = "2026-04-08T18:35:58.088727-04:00 myhost sshd[999]: session opened for user root"
    event = parse_syslog_line(line)
    assert event is not None
    assert event.host == "myhost"
    assert event.parsed["action"] == "session_opened"
