from pathlib import Path

from siem.collectors.docker import parse_docker_event
from siem.collectors.file_watcher import default_parser, detect_severity, extract_timestamp
from siem.collectors.network import parse_network_line
from siem.models.event import EventCategory, EventSeverity


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
