import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from siem.collectors.docker import parse_docker_event
from siem.collectors.file_watcher import default_parser, detect_severity, extract_timestamp
from siem.collectors.network import parse_network_line
from siem.models.event import Event, EventCategory, EventSeverity
from siem.tasks.collector_runner import CollectorRunner


# ── File watcher tests ──


def test_extract_timestamp_iso():
    ts = extract_timestamp("2024-03-22T10:15:32 something happened")
    assert ts.year == 2024
    assert ts.month == 3
    assert ts.hour == 10


def test_extract_timestamp_space():
    ts = extract_timestamp("2024-03-22 14:30:00 INFO starting up")
    assert ts.hour == 14
    assert ts.minute == 30


def test_detect_severity_critical():
    assert detect_severity("kernel panic - not syncing") == EventSeverity.CRITICAL


def test_detect_severity_high():
    assert detect_severity("ERROR: connection refused") == EventSeverity.HIGH


def test_detect_severity_medium():
    assert detect_severity("WARNING: disk usage 90%") == EventSeverity.MEDIUM


def test_detect_severity_low():
    assert detect_severity("INFO: server started") == EventSeverity.LOW


def test_default_parser():
    event = default_parser("2024-03-22T10:00:00 ERROR disk full", Path("/var/log/app.log"))
    assert event is not None
    assert event.source == "file"
    assert event.severity == EventSeverity.HIGH
    assert event.parsed["file"] == "/var/log/app.log"
    assert "disk full" in event.message


def test_default_parser_empty():
    assert default_parser("", Path("/tmp/test.log")) is None


# ── Docker collector tests ──


def test_parse_docker_container_start():
    data = {
        "status": "start",
        "Type": "container",
        "Action": "start",
        "Actor": {
            "ID": "abc123def456789",
            "Attributes": {"name": "web-app", "image": "nginx:latest"},
        },
        "time": 1711100000,
        "timeNano": 1711100000000000000,
    }
    event = parse_docker_event(data)
    assert event is not None
    assert event.source == "docker"
    assert event.category == EventCategory.APPLICATION
    assert event.parsed["action"] == "start"
    assert event.parsed["container_name"] == "web-app"
    assert event.parsed["image"] == "nginx:latest"
    assert "web-app" in event.message


def test_parse_docker_container_die():
    data = {
        "status": "die",
        "Type": "container",
        "Actor": {
            "ID": "abc123def456",
            "Attributes": {"name": "worker", "image": "python:3.12", "exitCode": "1"},
        },
        "time": 1711100000,
        "timeNano": 1711100000000000000,
    }
    event = parse_docker_event(data)
    assert event is not None
    assert event.severity == EventSeverity.HIGH
    assert event.parsed["exitCode"] == "1"


def test_parse_docker_network_event():
    data = {
        "status": "connect",
        "Type": "network",
        "Actor": {"ID": "net123", "Attributes": {"name": "bridge"}},
        "time": 1711100000,
        "timeNano": 1711100000000000000,
    }
    event = parse_docker_event(data)
    assert event is not None
    assert event.category == EventCategory.NETWORK


# ── Network collector tests ──


def test_parse_firewall_drop():
    line = (
        "Mar 22 10:15:32 myhost kernel: [UFW BLOCK] IN=eth0 OUT= "
        "MAC=aa:bb:cc:dd:ee:ff SRC=10.0.0.5 DST=192.168.1.1 "
        "LEN=60 PROTO=TCP SPT=54321 DPT=22"
    )
    event = parse_network_line(line)
    assert event is not None
    assert event.source == "network"
    assert event.category == EventCategory.NETWORK
    assert event.parsed["src_ip"] == "10.0.0.5"
    assert event.parsed["dst_ip"] == "192.168.1.1"
    assert event.parsed["proto"] == "TCP"
    assert event.parsed["dst_port"] == 22


def test_parse_firewall_suspicious_port():
    line = (
        "IN=eth0 OUT= SRC=10.0.0.99 DST=192.168.1.1 "
        "PROTO=TCP SPT=12345 DPT=4444"
    )
    event = parse_network_line(line)
    assert event is not None
    assert event.severity == EventSeverity.HIGH


def test_parse_dns_dnsmasq():
    line = "Mar 22 10:15:32 myhost dnsmasq[123]: query[A] example.com from 192.168.1.10"
    event = parse_network_line(line)
    assert event is not None
    assert event.parsed["action"] == "dns_query"
    assert event.parsed["domain"] == "example.com"
    assert event.parsed["client_ip"] == "192.168.1.10"


def test_parse_conntrack():
    line = (
        "conntrack v1.4.6: src=10.0.0.1 dst=93.184.216.34 "
        "sport=45678 dport=443 [NEW]"
    )
    event = parse_network_line(line)
    assert event is not None
    assert event.parsed["action"] == "conntrack_new"
    assert event.parsed["dst_port"] == 443


def test_parse_network_empty():
    assert parse_network_line("") is None
    assert parse_network_line("just some random text") is None


# ── Bulk indexer visibility ──


class _RecordingLogger:
    """Captures structlog calls so the level of a message can be asserted."""

    def __init__(self):
        self.calls = []

    def _record(self, level):
        def log(event, **kw):
            self.calls.append((level, event, kw))
        return log

    def __getattr__(self, name):
        return self._record(name)

    def levels_for(self, event):
        return [c[0] for c in self.calls if c[1] == event]


def test_a_partial_bulk_failure_warns_with_both_numbers(monkeypatch):
    """Regression: a reduced count was only ever logged at debug.

    index_events_bulk returns len(events) minus the rejected ones rather
    than raising, and the runner never compared that to the batch size. A
    mapping conflict or a run of 429s therefore sheds events at ~55k/day
    with no signal above debug.
    """
    recorder = _RecordingLogger()
    monkeypatch.setattr("siem.tasks.collector_runner.logger", recorder)

    CollectorRunner._log_indexed("events_indexed", 87, 100)

    assert recorder.levels_for("events_indexed") == []
    level, event, kw = recorder.calls[0]
    assert level == "warning"
    assert event == "events_index_partial_failure"
    # Both numbers, so the log says how much was lost and out of what.
    assert kw == {"indexed": 87, "attempted": 100, "failed": 13}


def test_a_fully_indexed_batch_stays_at_debug(monkeypatch):
    recorder = _RecordingLogger()
    monkeypatch.setattr("siem.tasks.collector_runner.logger", recorder)

    CollectorRunner._log_indexed("events_indexed", 100, 100)

    assert recorder.calls == [("debug", "events_indexed", {"count": 100})]


@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_dropping_a_batch_on_an_indexer_error_warns_with_the_count(monkeypatch):
    """The drop path loses up to 100 events; it must name the number."""
    recorder = _RecordingLogger()
    monkeypatch.setattr("siem.tasks.collector_runner.logger", recorder)

    async def boom(es, events):
        raise RuntimeError("es exploded")

    async def fake_es_client():
        return object()

    monkeypatch.setattr("siem.tasks.collector_runner.index_events_bulk", boom)
    monkeypatch.setattr("siem.tasks.collector_runner.get_es_client", fake_es_client)

    runner = CollectorRunner()
    for i in range(3):
        runner._queue.put_nowait(
            Event(
                timestamp=datetime.now(UTC),
                source="pihole",
                message=f"e{i}",
                host="h",
            )
        )

    task = asyncio.create_task(runner._bulk_indexer())
    for _ in range(50):
        await asyncio.sleep(0)
        if recorder.levels_for("events_dropped"):
            break
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert recorder.levels_for("events_dropped") == ["warning"]
    dropped = next(c for c in recorder.calls if c[1] == "events_dropped")
    assert dropped[2] == {"count": 3}
