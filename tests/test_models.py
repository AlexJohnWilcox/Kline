from siem.collectors.syslog import parse_syslog_line
from siem.models.event import EventCategory, EventSeverity


def test_parse_failed_ssh(sample_syslog_lines):
    event = parse_syslog_line(sample_syslog_lines[0])
    assert event is not None
    assert event.source == "syslog"
    assert event.category == EventCategory.AUTH
    assert event.severity == EventSeverity.MEDIUM
    assert event.parsed["action"] == "failed_login"
    assert event.parsed["user"] == "root"
    assert event.parsed["src_ip"] == "192.168.1.50"


def test_parse_accepted_ssh(sample_syslog_lines):
    event = parse_syslog_line(sample_syslog_lines[1])
    assert event is not None
    assert event.parsed["action"] == "successful_login"
    assert event.parsed["user"] == "alex"
    assert event.parsed["auth_method"] == "publickey"


def test_parse_sudo(sample_syslog_lines):
    event = parse_syslog_line(sample_syslog_lines[2])
    assert event is not None
    assert event.category == EventCategory.AUTH
    assert event.parsed["action"] == "sudo_command"
    assert "apt update" in event.parsed["command"]


def test_parse_oom_critical(sample_syslog_lines):
    event = parse_syslog_line(sample_syslog_lines[3])
    assert event is not None
    assert event.severity == EventSeverity.CRITICAL


def test_parse_cron(sample_syslog_lines):
    event = parse_syslog_line(sample_syslog_lines[4])
    assert event is not None
    assert event.category == EventCategory.SYSTEM
    assert event.parsed["process"] == "cron"


def test_parse_invalid_line():
    event = parse_syslog_line("this is not a valid syslog line")
    assert event is None


def test_event_to_es_doc(sample_syslog_lines):
    event = parse_syslog_line(sample_syslog_lines[0])
    doc = event.to_es_doc()
    assert doc["source"] == "syslog"
    assert doc["severity"] == "medium"
    assert isinstance(doc["timestamp"], str)
