import asyncio
import re
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncIterator

import structlog

from siem.collectors.base import BaseCollector
from siem.models.event import Event, EventCategory, EventSeverity

logger = structlog.get_logger()

# Traditional: "Mar 22 10:15:32 hostname process[pid]: message"
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# ISO 8601: "2026-04-08T18:35:58.088727-04:00 hostname process[pid]: message"
SYSLOG_ISO_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Patterns for categorizing and severity
AUTH_PROCESSES = {"sshd", "sudo", "login", "su", "passwd", "useradd", "userdel", "groupadd"}
FAILED_PATTERNS = re.compile(
    r"(?i)(fail|denied|error|invalid|unauthorized|rejected|refused|bad password)"
)
CRITICAL_PATTERNS = re.compile(
    r"(?i)(segfault|kernel panic|out of memory|oom-killer|critical)"
)

# The Oracle's dashboard collector authenticates to the Gate every 30 seconds,
# six to twelve dropbear lines a pass. Measured: that is the great majority of
# the Gate's entire 128 KB ring buffer. Keyed on the source ADDRESS rather than
# on dropbear, so a real login from anywhere else is still recorded.
DEFAULT_DROP_PATTERNS = [
    r"dropbear.*192\.168\.10\.2[:\s>]",
]


def should_ingest(line: str, patterns: list[str]) -> bool:
    """False when a line matches a configured drop pattern.

    A malformed pattern is ignored rather than raised: a typo in config must
    not stop the collector, and the failure mode of keeping a noisy line is
    far cheaper than the failure mode of ingesting nothing.
    """
    for pat in patterns:
        try:
            if re.search(pat, line):
                return False
        except re.error:
            logger.warning("syslog_drop_pattern_invalid", pattern=pat)
    return True


def parse_syslog_line(line: str) -> Event | None:
    """Parse a single syslog line into an Event."""
    line = line.strip()
    match = SYSLOG_PATTERN.match(line)
    iso_format = False
    if not match:
        match = SYSLOG_ISO_PATTERN.match(line)
        iso_format = True
    if not match:
        return None

    groups = match.groupdict()

    # Parse timestamp
    try:
        if iso_format:
            timestamp = datetime.fromisoformat(groups['timestamp'])
        else:
            ts_str = f"{datetime.now(UTC).year} {groups['timestamp']}"
            timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        timestamp = datetime.now(UTC)

    process = groups.get("process", "").split("/")[0]  # strip path prefixes
    message = groups.get("message", "")

    # Determine category
    category = EventCategory.SYSTEM
    if process.lower() in AUTH_PROCESSES:
        category = EventCategory.AUTH

    # Determine severity
    severity = EventSeverity.LOW
    if CRITICAL_PATTERNS.search(message):
        severity = EventSeverity.CRITICAL
    elif FAILED_PATTERNS.search(message):
        severity = EventSeverity.MEDIUM

    # Extract parsed fields
    parsed: dict = {
        "process": process,
    }
    if groups.get("pid"):
        parsed["pid"] = int(groups["pid"])

    # Extract common auth fields
    if category == EventCategory.AUTH:
        _extract_auth_fields(message, parsed)

    return Event(
        timestamp=timestamp,
        source="syslog",
        host=groups.get("host", socket.gethostname()),
        severity=severity,
        category=category,
        message=message,
        parsed=parsed,
        raw=line.strip(),
    )


def _extract_auth_fields(message: str, parsed: dict) -> None:
    """Extract common auth-related fields from the message."""
    # Failed password for user from IP
    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", message)
    if m:
        parsed["user"] = m.group(1)
        parsed["src_ip"] = m.group(2)
        parsed["action"] = "failed_login"
        return

    # Accepted password/publickey
    m = re.search(r"Accepted (\S+) for (\S+) from (\S+)", message)
    if m:
        parsed["auth_method"] = m.group(1)
        parsed["user"] = m.group(2)
        parsed["src_ip"] = m.group(3)
        parsed["action"] = "successful_login"
        return

    # sudo
    m = re.search(r"(\S+)\s*:\s*.*COMMAND=(.*)", message)
    if m:
        parsed["user"] = m.group(1)
        parsed["command"] = m.group(2).strip()
        parsed["action"] = "sudo_command"
        return

    # session opened/closed
    m = re.search(r"session (opened|closed) for user (\S+)", message)
    if m:
        parsed["action"] = f"session_{m.group(1)}"
        parsed["user"] = m.group(2)


class SyslogCollector(BaseCollector):
    """Collects events by tailing syslog files."""

    # Common syslog file locations
    DEFAULT_PATHS = [
        Path("/var/log/syslog"),
        Path("/var/log/messages"),
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
    ]

    def __init__(
        self,
        paths: list[Path] | None = None,
        drop_patterns: list[str] | None = None,
    ):
        super().__init__(name="syslog")
        self.paths = paths or [p for p in self.DEFAULT_PATHS if p.exists()]
        self.drop_patterns = (
            DEFAULT_DROP_PATTERNS if drop_patterns is None else drop_patterns
        )
        if not any(p.exists() for p in self.paths):
            searched = paths or self.DEFAULT_PATHS
            self.mark_blind(
                "no readable paths among: "
                + ", ".join(str(p) for p in searched)
            )

    async def collect(self) -> AsyncIterator[Event]:
        """Tail syslog files and yield events."""
        if not self.paths:
            logger.warning("no_syslog_files_found", searched=self.DEFAULT_PATHS)
            return

        logger.info("syslog_collector_watching", paths=[str(p) for p in self.paths])

        # Track file positions (start from end to avoid replaying old logs)
        positions: dict[Path, int] = {}
        for path in self.paths:
            try:
                positions[path] = path.stat().st_size
            except OSError:
                positions[path] = 0

        while True:
            for path in self.paths:
                try:
                    current_size = path.stat().st_size
                    last_pos = positions.get(path, 0)

                    # File was truncated (rotated)
                    if current_size < last_pos:
                        last_pos = 0

                    if current_size > last_pos:
                        with open(path) as f:
                            f.seek(last_pos)
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                if not should_ingest(line, self.drop_patterns):
                                    continue
                                event = parse_syslog_line(line)
                                if event:
                                    yield event
                            positions[path] = f.tell()

                except OSError as e:
                    logger.warning("syslog_read_error", path=str(path), error=str(e))

            await asyncio.sleep(1)  # poll interval
