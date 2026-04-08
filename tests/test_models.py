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


from datetime import UTC, datetime, timedelta
from siem.models.suppression import Suppression


def test_suppression_defaults():
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing",
        match_fields={"user": "alex"},
        source_alert_id="abc123",
    )
    assert s.id  # auto-generated
    assert s.status == "active"
    assert s.created_at is not None
    assert s.expires_at is None


def test_suppression_to_es_doc():
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing sudo",
        match_fields={"user": "alex"},
        source_alert_id="abc123",
        expires_at=datetime(2026, 4, 15, tzinfo=UTC),
    )
    doc = s.to_es_doc()
    assert doc["rule_id"] == "sudo-escalation"
    assert doc["status"] == "active"
    assert isinstance(doc["created_at"], str)
    assert isinstance(doc["expires_at"], str)
    assert doc["match_fields"] == {"user": "alex"}


def test_suppression_from_es_hit():
    hit = {
        "_id": "es-doc-id",
        "_source": {
            "id": "sup123",
            "created_at": "2026-04-08T12:00:00+00:00",
            "expires_at": "2026-04-15T12:00:00+00:00",
            "rule_id": "sudo-escalation",
            "reason": "testing",
            "match_fields": {"user": "alex"},
            "source_alert_id": "abc123",
            "status": "active",
        },
    }
    s = Suppression.from_es_hit(hit)
    assert s.id == "sup123"
    assert s.rule_id == "sudo-escalation"
    assert s.match_fields == {"user": "alex"}


def test_suppression_matches_context_full_match():
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing",
        match_fields={"user": "alex"},
        source_alert_id="abc123",
    )
    context = {"users": ["alex", "root"], "hosts": ["myhost"], "event_count": 6}
    assert s.matches_context(context) is True


def test_suppression_matches_context_no_match():
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing",
        match_fields={"user": "bob"},
        source_alert_id="abc123",
    )
    context = {"users": ["alex"], "hosts": ["myhost"], "event_count": 6}
    assert s.matches_context(context) is False


def test_suppression_matches_context_host():
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing",
        match_fields={"host": "myhost"},
        source_alert_id="abc123",
    )
    context = {"hosts": ["myhost", "other"], "event_count": 6}
    assert s.matches_context(context) is True


def test_suppression_matches_context_source_ip():
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing",
        match_fields={"source_ip": "10.0.0.1"},
        source_alert_id="abc123",
    )
    context = {"source_ips": ["10.0.0.1"], "event_count": 3}
    assert s.matches_context(context) is True


def test_suppression_matches_context_multi_field():
    s = Suppression(
        rule_id="sudo-escalation",
        reason="testing",
        match_fields={"user": "alex", "host": "myhost"},
        source_alert_id="abc123",
    )
    context = {"users": ["alex"], "hosts": ["myhost"], "event_count": 6}
    assert s.matches_context(context) is True
    context_miss = {"users": ["alex"], "hosts": ["otherhost"], "event_count": 6}
    assert s.matches_context(context_miss) is False


def test_suppression_is_expired():
    s = Suppression(
        rule_id="test",
        reason="test",
        match_fields={},
        source_alert_id="x",
        expires_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    assert s.is_expired() is True

    s2 = Suppression(
        rule_id="test",
        reason="test",
        match_fields={},
        source_alert_id="x",
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
    )
    assert s2.is_expired() is False

    s3 = Suppression(
        rule_id="test",
        reason="test",
        match_fields={},
        source_alert_id="x",
        expires_at=None,
    )
    assert s3.is_expired() is False
