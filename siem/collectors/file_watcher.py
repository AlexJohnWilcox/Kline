import asyncio
import re
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncIterator, Callable

import structlog

from siem.collectors.base import BaseCollector
from siem.models.event import Event, EventCategory, EventSeverity

logger = structlog.get_logger()

# Generic timestamp patterns to try in order
TIMESTAMP_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ISO 8601: 2024-03-22T10:15:32
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
    # ISO with space: 2024-03-22 10:15:32
    (re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
    # Syslog-style: Mar 22 10:15:32
    (re.compile(r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"), None),  # handled specially
]

SEVERITY_PATTERNS: dict[EventSeverity, re.Pattern] = {
    EventSeverity.CRITICAL: re.compile(
        r"(?i)\b(CRITICAL|FATAL|EMERG|PANIC|segfault|kernel panic|out of memory)\b"
    ),
    EventSeverity.HIGH: re.compile(r"(?i)\b(ERROR|ALERT|CRIT)\b"),
    EventSeverity.MEDIUM: re.compile(
        r"(?i)\b(WARN|WARNING|FAIL|DENIED|REFUSED|REJECTED)\b"
    ),
}


def extract_timestamp(line: str) -> datetime:
    """Try to extract a timestamp from a log line."""
    for pattern, fmt in TIMESTAMP_PATTERNS:
        m = pattern.search(line)
        if m:
            ts_str = m.group(1)
            if fmt is None:
                # Syslog-style: prepend current year
                ts_str = f"{datetime.now(UTC).year} {ts_str}"
                try:
                    return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                except ValueError:
                    continue
            else:
                try:
                    return datetime.strptime(ts_str, fmt)
                except ValueError:
                    continue
    return datetime.now(UTC)


def detect_severity(line: str) -> EventSeverity:
    """Detect severity from log line content."""
    for severity, pattern in SEVERITY_PATTERNS.items():
        if pattern.search(line):
            return severity
    return EventSeverity.LOW


def default_parser(line: str, file_path: Path) -> Event | None:
    """Default log line parser — extracts timestamp, severity, keeps the rest as message."""
    line = line.strip()
    if not line:
        return None

    return Event(
        timestamp=extract_timestamp(line),
        source="file",
        host=socket.gethostname(),
        severity=detect_severity(line),
        category=EventCategory.APPLICATION,
        message=line,
        parsed={"file": str(file_path)},
        tags=["file-watcher"],
        raw=line,
    )


class FileWatcherCollector(BaseCollector):
    """Tail arbitrary log files and emit events.

    Accepts a list of (path, parser) tuples. If no parser is given, a
    generic parser is used that extracts timestamps and severity keywords.
    """

    def __init__(
        self,
        watch_paths: list[tuple[Path, Callable[[str, Path], Event | None] | None]] | None = None,
    ):
        super().__init__(name="file")
        self.watch_paths: list[tuple[Path, Callable[[str, Path], Event | None]]] = []
        for path, parser in (watch_paths or []):
            self.watch_paths.append((path, parser or default_parser))

    def add_path(
        self,
        path: Path,
        parser: Callable[[str, Path], Event | None] | None = None,
    ) -> None:
        self.watch_paths.append((path, parser or default_parser))

    async def collect(self) -> AsyncIterator[Event]:
        existing = [(p, fn) for p, fn in self.watch_paths if p.exists()]
        if not existing:
            logger.warning(
                "file_watcher_no_files",
                paths=[str(p) for p, _ in self.watch_paths],
            )
            return

        logger.info(
            "file_watcher_watching",
            paths=[str(p) for p, _ in existing],
        )

        # Start from end of each file
        positions: dict[Path, int] = {}
        for path, _ in existing:
            try:
                positions[path] = path.stat().st_size
            except OSError:
                positions[path] = 0

        while True:
            for path, parser in existing:
                try:
                    current_size = path.stat().st_size
                    last_pos = positions.get(path, 0)

                    if current_size < last_pos:
                        last_pos = 0  # file rotated

                    if current_size > last_pos:
                        with open(path) as f:
                            f.seek(last_pos)
                            for line in f:
                                event = parser(line, path)
                                if event:
                                    yield event
                            positions[path] = f.tell()
                except OSError as e:
                    logger.warning("file_watcher_read_error", path=str(path), error=str(e))

            await asyncio.sleep(1)
