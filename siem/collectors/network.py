import asyncio
import re
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncIterator

import structlog

from siem.collectors.base import BaseCollector
from siem.collectors.path_health import MISSING_GRACE_PASSES, PathHealth
from siem.models.event import Event, EventCategory, EventSeverity

logger = structlog.get_logger()

# ── iptables/nftables log patterns ──

# Kernel firewall log: "IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=54321 DPT=22"
NETFILTER_PATTERN = re.compile(
    r"(?:IN=(?P<in_iface>\S*))?\s*"
    r"(?:OUT=(?P<out_iface>\S*))?\s*"
    r"(?:MAC=(?P<mac>\S+))?\s*"
    r"SRC=(?P<src_ip>\S+)\s+"
    r"DST=(?P<dst_ip>\S+)\s+"
    r".*?"
    r"PROTO=(?P<proto>\S+)"
    r"(?:.*?SPT=(?P<src_port>\d+))?"
    r"(?:.*?DPT=(?P<dst_port>\d+))?"
)

# Firewall action prefix (commonly logged by iptables LOG target)
FIREWALL_ACTION_PATTERN = re.compile(
    r"\b(?P<action>DROP|REJECT|ACCEPT|BLOCK|DENY|ALLOW)\b", re.IGNORECASE
)

# ── DNS query log patterns ──

# dnsmasq: "query[A] example.com from 192.168.1.10"
DNSMASQ_PATTERN = re.compile(
    r"query\[(?P<qtype>\S+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client_ip>\S+)"
)

# systemd-resolved style: "Outgoing query: example.com IN A"
RESOLVED_PATTERN = re.compile(
    r"(?:query|lookup).*?(?P<domain>[\w.-]+\.\w{2,})\s+IN\s+(?P<qtype>\w+)"
)

# conntrack: "conntrack ... src=1.2.3.4 dst=5.6.7.8 sport=1234 dport=80 ... [NEW|ESTABLISHED|DESTROY]"
CONNTRACK_PATTERN = re.compile(
    r"src=(?P<src_ip>\S+)\s+dst=(?P<dst_ip>\S+)\s+"
    r"sport=(?P<src_port>\d+)\s+dport=(?P<dst_port>\d+)"
    r".*?\[(?P<state>NEW|ESTABLISHED|DESTROY|UNREPLIED)\]",
    re.IGNORECASE,
)

# Well-known suspicious ports
SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 12345, 9001}

# Common DNS log file locations
DNS_LOG_PATHS = [
    Path("/var/log/dnsmasq.log"),
    Path("/var/log/pihole.log"),
]

# Firewall log locations
FIREWALL_LOG_PATHS = [
    Path("/var/log/kern.log"),
    Path("/var/log/ufw.log"),
    Path("/var/log/firewall"),
    Path("/var/log/iptables.log"),
    Path("/var/log/nftables.log"),
    Path("/var/log/messages"),
]


def _parse_firewall_line(line: str) -> Event | None:
    """Parse a netfilter/iptables/nftables log line."""
    match = NETFILTER_PATTERN.search(line)
    if not match:
        return None

    groups = match.groupdict()
    action_match = FIREWALL_ACTION_PATTERN.search(line)
    action = action_match.group("action").upper() if action_match else "LOG"

    dst_port = int(groups.get("dst_port") or 0)
    proto = groups.get("proto", "").upper()

    severity = EventSeverity.LOW
    if action in ("DROP", "REJECT", "BLOCK", "DENY"):
        severity = EventSeverity.MEDIUM
    if dst_port in SUSPICIOUS_PORTS:
        severity = EventSeverity.HIGH

    parsed = {
        "action": f"firewall_{action.lower()}",
        "src_ip": groups.get("src_ip"),
        "dst_ip": groups.get("dst_ip"),
        "proto": proto,
    }
    if groups.get("src_port"):
        parsed["src_port"] = int(groups["src_port"])
    if dst_port:
        parsed["dst_port"] = dst_port
    if groups.get("in_iface"):
        parsed["in_iface"] = groups["in_iface"]
    if groups.get("out_iface"):
        parsed["out_iface"] = groups["out_iface"]

    tags = ["firewall", proto.lower()]
    if action in ("DROP", "REJECT", "BLOCK", "DENY"):
        tags.append("blocked")

    message = (
        f"Firewall {action}: {groups.get('src_ip')}:{groups.get('src_port', '?')}"
        f" -> {groups.get('dst_ip')}:{dst_port or '?'} ({proto})"
    )

    return Event(
        timestamp=datetime.now(UTC),
        source="network",
        host=socket.gethostname(),
        severity=severity,
        category=EventCategory.NETWORK,
        message=message,
        parsed=parsed,
        tags=tags,
        raw=line.strip(),
    )


def _parse_dns_line(line: str) -> Event | None:
    """Parse a DNS query log line (dnsmasq or systemd-resolved)."""
    match = DNSMASQ_PATTERN.search(line)
    if match:
        groups = match.groupdict()
        return Event(
            timestamp=datetime.now(UTC),
            source="network",
            host=socket.gethostname(),
            severity=EventSeverity.LOW,
            category=EventCategory.NETWORK,
            message=f"DNS query: {groups['domain']} ({groups['qtype']}) from {groups['client_ip']}",
            parsed={
                "action": "dns_query",
                "domain": groups["domain"],
                "qtype": groups["qtype"],
                "client_ip": groups["client_ip"],
            },
            tags=["dns"],
            raw=line.strip(),
        )

    match = RESOLVED_PATTERN.search(line)
    if match:
        groups = match.groupdict()
        return Event(
            timestamp=datetime.now(UTC),
            source="network",
            host=socket.gethostname(),
            severity=EventSeverity.LOW,
            category=EventCategory.NETWORK,
            message=f"DNS query: {groups['domain']} ({groups.get('qtype', 'A')})",
            parsed={
                "action": "dns_query",
                "domain": groups["domain"],
                "qtype": groups.get("qtype", "A"),
            },
            tags=["dns"],
            raw=line.strip(),
        )

    return None


def _parse_conntrack_line(line: str) -> Event | None:
    """Parse a conntrack log line."""
    match = CONNTRACK_PATTERN.search(line)
    if not match:
        return None

    groups = match.groupdict()
    state = groups.get("state", "").upper()
    dst_port = int(groups.get("dst_port", 0))

    severity = EventSeverity.LOW
    if dst_port in SUSPICIOUS_PORTS:
        severity = EventSeverity.HIGH
    elif state == "NEW":
        severity = EventSeverity.LOW

    return Event(
        timestamp=datetime.now(UTC),
        source="network",
        host=socket.gethostname(),
        severity=severity,
        category=EventCategory.NETWORK,
        message=(
            f"Connection {state}: {groups['src_ip']}:{groups['src_port']}"
            f" -> {groups['dst_ip']}:{dst_port}"
        ),
        parsed={
            "action": f"conntrack_{state.lower()}",
            "src_ip": groups["src_ip"],
            "dst_ip": groups["dst_ip"],
            "src_port": int(groups["src_port"]),
            "dst_port": dst_port,
            "state": state,
        },
        tags=["conntrack", state.lower()],
        raw=line.strip(),
    )


def parse_network_line(line: str) -> Event | None:
    """Try all network parsers on a line, return first match."""
    line = line.strip()
    if not line:
        return None

    # Try firewall first (most structured)
    event = _parse_firewall_line(line)
    if event:
        return event

    # DNS
    event = _parse_dns_line(line)
    if event:
        return event

    # Conntrack
    event = _parse_conntrack_line(line)
    if event:
        return event

    return None


class NetworkCollector(BaseCollector):
    """Collect events from firewall logs, DNS query logs, and conntrack.

    Auto-discovers common log file locations on Linux systems.
    """

    # Consecutive passes a watched path may be absent before the collector
    # calls itself blind. See siem/collectors/path_health.py.
    MISSING_GRACE_PASSES = MISSING_GRACE_PASSES

    def __init__(
        self,
        firewall_paths: list[Path] | None = None,
        dns_paths: list[Path] | None = None,
    ):
        super().__init__(name="network")
        self.firewall_paths = firewall_paths or [p for p in FIREWALL_LOG_PATHS if p.exists()]
        self.dns_paths = dns_paths or [p for p in DNS_LOG_PATHS if p.exists()]
        if not any(p.exists() for p in self.all_paths):
            searched = (firewall_paths or FIREWALL_LOG_PATHS) + (dns_paths or DNS_LOG_PATHS)
            self.mark_blind(
                "no readable paths among: "
                + ", ".join(str(p) for p in searched)
            )

    @property
    def all_paths(self) -> list[Path]:
        return self.firewall_paths + self.dns_paths

    async def collect(self) -> AsyncIterator[Event]:
        # Every configured path, present or not -- the same set syslog.py
        # watches. Dropping the absent ones here is how a configured path
        # that has not been created yet became invisible: it was filtered
        # out before the loop that would have reported it missing.
        # Auto-discovery has already filtered to existing paths in __init__,
        # so this only widens the set for an explicitly configured one.
        paths = self.all_paths
        if not paths:
            logger.warning(
                "network_collector_no_files",
                firewall=FIREWALL_LOG_PATHS,
                dns=DNS_LOG_PATHS,
            )
            return

        logger.info("network_collector_watching", paths=[str(p) for p in paths])

        # Start from end of each file
        positions: dict[Path, int] = {}
        for path in paths:
            try:
                positions[path] = path.stat().st_size
            except OSError:
                positions[path] = 0

        # The same bookkeeping the syslog collector runs. Before this, a
        # kern.log that existed but was root:adm 0640 -- the normal
        # permission on Debian-family hosts -- read as "ok" forever.
        health = PathHealth(
            paths,
            log_event="network_read_error",
            grace_passes=self.MISSING_GRACE_PASSES,
        )

        while True:
            health.begin_pass()
            for path in paths:
                try:
                    current_size = path.stat().st_size
                    last_pos = positions.get(path, 0)

                    if current_size < last_pos:
                        last_pos = 0

                    # >= rather than > : a file that never grows again after
                    # priming is otherwise never opened, so a permission
                    # revoked with no further writes never surfaces. The
                    # extra open+seek-to-EOF on an unchanged file is a no-op.
                    if current_size >= last_pos:
                        with open(path) as f:
                            f.seek(last_pos)
                            for line in f:
                                event = parse_network_line(line)
                                if event:
                                    yield event
                            positions[path] = f.tell()
                except OSError as e:
                    health.failed(path, e)
                else:
                    health.ok(path)

            health.apply(self)

            await asyncio.sleep(1)
