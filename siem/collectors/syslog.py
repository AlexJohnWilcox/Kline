import asyncio
import re
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import AsyncIterator

import structlog

from siem.collectors.base import BaseCollector
from siem.collectors.path_health import MISSING_GRACE_PASSES, PathHealth
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

# OpenWrt logread raw replay: only ever seen on a boot-time replay of the
# Gate's raw `logread` output, appended straight to the tailed file. The
# live feed never looks like this - the receiving syslog daemon rewrites it
# into SYSLOG_PATTERN before it touches disk.
#
#   "Thu Sep 18 03:11:50 2026 daemon.notice rotate-road[123]: message"
#
# Four-digit year, a leading weekday, and a facility.level field sitting
# where BSD syslog would put a hostname - these lines carry no hostname at
# all. "host" is deliberately not a named group here; parse_syslog_line
# hardcodes it, since every line in this format comes from the Gate.
SYSLOG_OPENWRT_PATTERN = re.compile(
    r"^\w{3}\s+"
    r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+"
    r"(?P<facility>\w+)\.(?P<level>\w+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Every one of these lines is emitted by the Gate, so its host is hardcoded
# rather than left to default to this machine's own hostname.
OPENWRT_HOST = "gate"

# syslog facility.level -> minimum severity. Applied as a floor, not an
# override: message-text detection (FAILED_PATTERNS / CRITICAL_PATTERNS)
# can still push severity higher, e.g. rotate-road logs its own rollback at
# .notice but the "FAIL ... did not carry traffic" text still means MEDIUM.
SYSLOG_LEVEL_SEVERITY = {
    "emerg": EventSeverity.CRITICAL,
    "panic": EventSeverity.CRITICAL,
    "alert": EventSeverity.CRITICAL,
    "crit": EventSeverity.CRITICAL,
    "err": EventSeverity.HIGH,
    "error": EventSeverity.HIGH,
    "warning": EventSeverity.MEDIUM,
    "warn": EventSeverity.MEDIUM,
    "notice": EventSeverity.LOW,
    "info": EventSeverity.LOW,
    "debug": EventSeverity.LOW,
}
_SEVERITY_ORDER = [
    EventSeverity.LOW,
    EventSeverity.MEDIUM,
    EventSeverity.HIGH,
    EventSeverity.CRITICAL,
]

# Patterns for categorizing and severity
# "dropbear" is the Gate's only SSH daemon. Without it here the category
# stays SYSTEM, _extract_auth_fields is never called, and every auth line
# from the router is filed as ordinary noise.
AUTH_PROCESSES = {
    "sshd",
    "dropbear",
    "sudo",
    "login",
    "su",
    "passwd",
    "useradd",
    "userdel",
    "groupadd",
}
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
    fmt = "bsd"
    match = SYSLOG_PATTERN.match(line)
    if not match:
        match = SYSLOG_ISO_PATTERN.match(line)
        fmt = "iso"
    if not match:
        match = SYSLOG_OPENWRT_PATTERN.match(line)
        fmt = "openwrt"
    if not match:
        return None

    groups = match.groupdict()

    # Parse timestamp.
    #
    # BSD and OpenWrt lines carry local wall-clock time and no offset. Both
    # the Gate and this host run on local time, so a naive value from either
    # format is local. It must be made aware here: Event.to_es_doc()
    # serialises with .isoformat(), and Elasticsearch reads an offset-less
    # date as UTC -- which silently backdates every event by the local
    # offset (four hours here) and puts it outside every detection window.
    #
    # datetime.astimezone(UTC) on a naive value interprets it as local and
    # converts, which is exactly the needed semantics; on an already-aware
    # value (the ISO format carries its own offset) it is a plain conversion
    # and cannot double-shift.
    try:
        if fmt == "iso":
            timestamp = datetime.fromisoformat(groups["timestamp"]).astimezone(UTC)
        elif fmt == "openwrt":
            timestamp = datetime.strptime(  # noqa: DTZ007 - local by format, see above
                groups["timestamp"], "%b %d %H:%M:%S %Y"
            ).astimezone(UTC)
        else:
            # BSD syslog carries no year, so it has to be inferred -- from
            # the *local* year, since that is the clock that wrote the line.
            # Using the UTC year is wrong for the last hours of 31 December,
            # when UTC has already rolled over and local time has not.
            local_now = datetime.now(UTC).astimezone()
            ts_str = f"{local_now.year} {groups['timestamp']}"
            naive = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")  # noqa: DTZ007
            # The other half of the New Year boundary: on 1 January a line
            # stamped "Dec 31 23:59" takes the new year and lands twelve
            # months in the future, outside every window in the same way the
            # missing offset put it in the past. Nothing a tail-from-EOF
            # collector reads is legitimately a day ahead of now, so treat
            # that as last year's December.
            if naive.astimezone(UTC) - local_now > timedelta(days=1):
                naive = naive.replace(year=naive.year - 1)
            timestamp = naive.astimezone(UTC)
    except ValueError:
        timestamp = datetime.now(UTC)

    process = groups.get("process", "").split("/")[0]  # strip path prefixes
    message = groups.get("message", "")

    # Determine category
    category = EventCategory.SYSTEM
    if process.lower() in AUTH_PROCESSES:
        category = EventCategory.AUTH

    # Determine severity from the message text
    severity = EventSeverity.LOW
    if CRITICAL_PATTERNS.search(message):
        severity = EventSeverity.CRITICAL
    elif FAILED_PATTERNS.search(message):
        severity = EventSeverity.MEDIUM

    # OpenWrt lines carry an explicit facility.level; treat it as a floor so
    # an "err"/"crit" line is never buried at LOW just because its message
    # text doesn't happen to match FAILED_PATTERNS/CRITICAL_PATTERNS.
    if fmt == "openwrt":
        level_severity = SYSLOG_LEVEL_SEVERITY.get((groups.get("level") or "").lower())
        if level_severity is not None and (
            _SEVERITY_ORDER.index(level_severity) > _SEVERITY_ORDER.index(severity)
        ):
            severity = level_severity

    # Extract parsed fields
    parsed: dict = {
        "process": process,
    }
    if groups.get("pid"):
        parsed["pid"] = int(groups["pid"])
    if fmt == "openwrt":
        parsed["facility"] = f"{groups['facility']}.{groups['level']}"

    # Extract common auth fields
    if category == EventCategory.AUTH:
        _extract_auth_fields(message, parsed)

    host = groups.get("host") or (OPENWRT_HOST if fmt == "openwrt" else socket.gethostname())

    return Event(
        timestamp=timestamp,
        source="syslog",
        host=host,
        severity=severity,
        category=category,
        message=message,
        parsed=parsed,
        raw=line.strip(),
    )


def _split_source(addr: str) -> tuple[str, int | None]:
    """Split dropbear's ``IP:PORT`` peer into its parts.

    sshd writes ``1.2.3.4 port 22``; dropbear writes ``1.2.3.4:41234``.
    An IPv6 peer carries colons of its own, so only the unambiguous
    single-colon form is split — a whole address beats a truncated one.
    """
    host, sep, port = addr.rpartition(":")
    if sep and host and ":" not in host and port.isdigit():
        return host, int(port)
    return addr, None


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

    # dropbear: Bad password attempt for 'root' from 1.2.3.4:41234
    # (also "Bad PAM password attempt" when PAM is compiled in)
    m = re.search(r"Bad (?:PAM )?password attempt for '([^']*)' from (\S+)", message)
    if m:
        parsed["user"] = m.group(1)
        parsed["src_ip"], port = _split_source(m.group(2))
        if port is not None:
            parsed["src_port"] = port
        parsed["action"] = "failed_login"
        return

    # dropbear: Login attempt for nonexistent user from 1.2.3.4:41234
    # The line carries no username. Leave "user" unset rather than invent one.
    m = re.search(r"Login attempt for nonexistent user from (\S+)", message)
    if m:
        parsed["src_ip"], port = _split_source(m.group(1))
        if port is not None:
            parsed["src_port"] = port
        parsed["action"] = "failed_login"
        return

    # dropbear: Pubkey auth succeeded for 'root' with ssh-ed25519 key
    #           SHA256:... from 1.2.3.4:41234
    # dropbear: Password auth succeeded for 'alex' from 1.2.3.4:41234
    # The greedy .* is deliberate: the pubkey line's fingerprint sits between
    # the username and the peer, so the peer must be taken from the LAST
    # " from " in the line.
    m = re.search(r"(Password|Pubkey) auth succeeded for '([^']*)'.* from (\S+)", message)
    if m:
        parsed["auth_method"] = m.group(1).lower()
        parsed["user"] = m.group(2)
        parsed["src_ip"], port = _split_source(m.group(3))
        if port is not None:
            parsed["src_port"] = port
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

    # Consecutive passes a configured path may be absent before the
    # collector calls itself blind. Exposed on the class so tests can drive
    # the grace period without sleeping through it.
    MISSING_GRACE_PASSES = MISSING_GRACE_PASSES

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
                # Priming only. A path that cannot be stat'd starts at 0; if
                # the cause is permissions, the main loop marks blind on its
                # first pass rather than this one guessing.
                positions[path] = 0

        # Read outcomes across passes, and the blind flag they imply. See
        # siem/collectors/path_health.py for the three rules it enforces.
        health = PathHealth(
            self.paths,
            log_event="syslog_read_error",
            grace_passes=self.MISSING_GRACE_PASSES,
        )

        while True:
            health.begin_pass()
            for path in self.paths:
                try:
                    current_size = path.stat().st_size
                    last_pos = positions.get(path, 0)

                    # File was truncated (rotated)
                    if current_size < last_pos:
                        last_pos = 0

                    # >= rather than > : a file that never grows again after
                    # priming (e.g. permission revoked with no further writes)
                    # would otherwise never be opened, and a PermissionError
                    # that only stat() (not open()) would swallow would go
                    # undetected forever. The extra open+seek-to-EOF on an
                    # unchanged, readable file is a no-op cost.
                    if current_size >= last_pos:
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
                    # Every read failure -- permission, absence, or anything
                    # else -- is classified in one place. The previous shape
                    # popped the path on OSError, and FileNotFoundError is an
                    # OSError, so a configured-but-absent path emptied the
                    # bookkeeping and cleared the construction-time blind
                    # flag within a second of startup.
                    health.failed(path, e)
                else:
                    health.ok(path)

            health.apply(self)

            await asyncio.sleep(1)  # poll interval
