import asyncio
import json
import re
import socket
from collections import OrderedDict
from datetime import UTC, datetime
from typing import AsyncIterator

import httpx
import structlog

from siem.collectors.base import BaseCollector
from siem.models.event import Event, EventCategory, EventSeverity

logger = structlog.get_logger()

# Docker socket path
DOCKER_SOCKET = "/var/run/docker.sock"

# Patterns for security-relevant Docker events
PRIVILEGED_PATTERN = re.compile(r"privileged", re.IGNORECASE)

# Docker event signatures that are never indexed.
#
# Kline's own Elasticsearch runs a healthcheck every ten seconds, and each run
# emits exec_create, exec_start and exec_die. Measured on the live deployment:
# 180 events per ten minutes, 25,920 a day, 43% of everything collected in 48
# hours -- the instrument spending itself watching its own heartbeat, and
# skewing the volume baseline the anomaly detector is built on.
#
# The default is anchored and exact, and it is deliberately not a loose
# substring match on the command. An earlier version matched
# `exec_\w+: .*/_cluster/health` anywhere in the signature, which was an
# evasion vector in a security tool: anyone with exec access to ANY container
# could append `# /_cluster/health` to a command and suppress the logging of
# their own exec. It also swallowed a second Elasticsearch-backed container's
# legitimate healthcheck, since it never looked at which container it was.
#
# Matching the whole signature ties the drop to Docker's own labels -- the
# compose project and container name, which the command cannot forge -- so
# only Kline's own Elasticsearch healthcheck, running exactly the command
# Kline's compose file gives it, is ever dropped. If that command changes the
# pattern stops matching and the noise comes back, which is the right way for
# this to fail: noisily, not blindly.
#
# It also does NOT drop every exec. `docker exec -it siem-elasticsearch bash`
# is someone getting a shell inside the database, which is exactly what a
# SIEM is for.
DEFAULT_DROP_PATTERNS = [
    (
        r"^kline siem-elasticsearch exec_\w+: /bin/sh -c "
        r"curl -f http://localhost:9200/_cluster/health \|\| exit 1$"
    )
]

# How many filtered exec ids to remember while waiting for their exec_die.
# At the observed rate of one healthcheck every ten seconds this is hours of
# slack; it exists only so a die that never arrives cannot grow the map.
_EXEC_MEMORY = 256

# Verbs that are alarming whatever the circumstances.
_HIGH_ACTIONS = {"kill", "oom"}
# Administrative verbs: worth recording, not worth waking anyone.
_MEDIUM_ACTIONS = {
    "stop",
    "restart",
    "update",
    "rename",
    "pause",
    "exec_create",
    "exec_start",
}


def _split_action(raw: str) -> tuple[str, str]:
    """Split Docker's action into its verb and any trailing detail.

    Docker reports an exec as the whole command line -- `exec_start: /bin/sh
    -c curl -f http://localhost:9200/_cluster/health || exit 1`. Storing that
    in `parsed.action` put unbounded-cardinality text in a field mapped
    `keyword`, and it also meant the severity table could never match
    `exec_create` or `exec_start`, because it was comparing a verb against a
    command.
    """
    verb, _, detail = raw.partition(":")
    return verb.strip(), detail.strip()


def should_ingest(
    data: dict,
    patterns: list[str],
    dropped_execs: "OrderedDict[str, None] | None" = None,
) -> bool:
    """False when this event matches a drop pattern.

    Patterns are matched against `<compose project> <container name>
    <action>`, so they can target a project, a container, a verb, a command,
    or any combination. The project and name come from Docker's own labels
    and cannot be influenced by the command being run -- which is why they
    are in the signature at all. Anchor your patterns: an unanchored one
    that matches only on command text lets any container opt itself out of
    logging by embedding the magic substring.

    `patterns` must be a list -- the collector resolves an unset setting to
    DEFAULT_DROP_PATTERNS before calling, and an explicitly empty list means
    "drop nothing", a distinction None would erase. `dropped_execs`, by
    contrast, may be None: "do not correlate" is a sensible default, whereas
    there is no safe default set of patterns. Do not make them symmetric.

    `dropped_execs` correlates the three events a single exec produces.
    Docker reports exec_create and exec_start with the command attached, but
    exec_die with only an execID -- so the die of a filtered healthcheck is
    indistinguishable from the die of a real `docker exec` unless the
    create/start is remembered. Replaying 2,000 real events from the live
    index showed a third of the healthcheck surviving the filter without it.

    The map is bounded: an id is forgotten when its die arrives, and the
    oldest are evicted past _EXEC_MEMORY so a die that never comes cannot
    grow it without limit. Eviction fails in the safe direction -- an evicted
    id's die is kept, so a stray healthcheck die is ingested. It can never
    cause a real exec's die to be dropped, because only ids that were
    themselves filtered ever enter the map.
    """
    if patterns is None:
        raise TypeError("patterns must be a list; resolve None to a default first")
    attributes = data.get("Actor", {}).get("Attributes", {})
    name = attributes.get("name", "")
    project = attributes.get("com.docker.compose.project", "")
    action = data.get("status") or data.get("Action", "")
    exec_id = attributes.get("execID")

    if (
        dropped_execs is not None
        and exec_id is not None
        and action.partition(":")[0].strip() == "exec_die"
        and exec_id in dropped_execs
    ):
        del dropped_execs[exec_id]
        return False

    signature = f"{project} {name} {action}"
    matched = False
    for pattern in patterns:
        try:
            if re.search(pattern, signature):
                matched = True
                break
        except re.error:
            # A typo in config must not stop the collector. Keeping a noisy
            # event is far cheaper than ingesting nothing -- and an uncaught
            # error here escapes to the per-connection handler, which tears
            # down and reopens the whole /events stream on every event.
            logger.warning("docker_drop_pattern_invalid", pattern=pattern)

    if matched:
        if dropped_execs is not None and exec_id is not None:
            dropped_execs[exec_id] = None
            while len(dropped_execs) > _EXEC_MEMORY:
                dropped_execs.popitem(last=False)
        return False
    return True


def _severity_for_action(action: str, attributes: dict) -> EventSeverity:
    """Grade a Docker event by its outcome, not by its verb alone.

    `die` and `destroy` used to be unconditionally HIGH. But a container
    exiting cleanly and then being removed is the most ordinary thing in
    Docker, and grading it HIGH is what let a code review's throwaway
    containers fire `high-error-rate` twenty times.
    """
    if action == "die":
        # No exit code is not evidence of a clean exit, so do not assume one.
        return (
            EventSeverity.LOW
            if attributes.get("exitCode") == "0"
            else EventSeverity.HIGH
        )
    if action == "destroy":
        # Removal follows a stop; whatever happened was already reported by
        # the preceding die, with its exit code attached.
        return EventSeverity.LOW
    if action in _HIGH_ACTIONS:
        return EventSeverity.HIGH
    if action in _MEDIUM_ACTIONS:
        return EventSeverity.MEDIUM
    return EventSeverity.LOW


def _category_for_type(event_type: str) -> EventCategory:
    """Map Docker event types to categories."""
    if event_type == "network":
        return EventCategory.NETWORK
    return EventCategory.APPLICATION


def parse_docker_event(data: dict) -> Event | None:
    """Parse a Docker API event into a SIEM Event."""
    raw_action = data.get("status") or data.get("Action", "")
    status, detail = _split_action(raw_action)
    event_type = data.get("Type", "container")
    actor = data.get("Actor", {})
    attributes = actor.get("Attributes", {})

    container_name = attributes.get("name", "")
    image = attributes.get("image", "")
    container_id = actor.get("ID", "")[:12]

    # Timestamp from Docker (nanoseconds epoch)
    ts_nano = data.get("timeNano", 0)
    if ts_nano:
        timestamp = datetime.fromtimestamp(ts_nano / 1e9, tz=UTC)
    else:
        ts = data.get("time", 0)
        timestamp = datetime.fromtimestamp(ts, tz=UTC) if ts else datetime.now(UTC)

    severity = _severity_for_action(status, attributes)

    # Escalate severity if privileged
    raw_str = json.dumps(data)
    if PRIVILEGED_PATTERN.search(raw_str):
        severity = EventSeverity.CRITICAL

    message = f"docker {event_type} {status}: {container_name or container_id}"
    if image:
        message += f" ({image})"

    parsed = {
        "action": status,
        "docker_type": event_type,
        "container_id": container_id,
        "container_name": container_name,
        "image": image,
    }
    if detail:
        # The command an exec ran, kept out of `action` so that field stays a
        # low-cardinality verb.
        parsed["exec_command"] = detail
    # Which compose project owns this container -- "kline" marks the SIEM's
    # own infrastructure, so self-generated events stay identifiable even
    # when they are deliberately kept.
    compose_project = attributes.get("com.docker.compose.project")
    if compose_project:
        parsed["compose_project"] = compose_project

    # Include extra attributes (labels, exit codes, etc.)
    for key in ("exitCode", "signal", "execID"):
        if key in attributes:
            parsed[key] = attributes[key]

    tags = ["docker", event_type]
    if severity >= EventSeverity.HIGH:
        tags.append("security")

    return Event(
        timestamp=timestamp,
        source="docker",
        host=socket.gethostname(),
        severity=severity,
        category=_category_for_type(event_type),
        message=message,
        parsed=parsed,
        tags=tags,
        raw=raw_str,
    )


class DockerCollector(BaseCollector):
    """Collect events from the Docker daemon via its API.

    Connects to the Docker socket and streams system events (container
    start/stop/die, network connect/disconnect, image pull, etc.).
    """

    def __init__(
        self,
        socket_path: str = DOCKER_SOCKET,
        drop_patterns: list[str] | None = None,
    ):
        super().__init__(name="docker")
        self.socket_path = socket_path
        # None means "use the defaults"; an explicitly empty list means "drop
        # nothing". Collapsing the two would leave no way to turn dropping
        # off, which is the mistake SYSLOG_DROP_PATTERNS already made once.
        self.drop_patterns = (
            DEFAULT_DROP_PATTERNS if drop_patterns is None else drop_patterns
        )
        # execIDs of filtered execs, awaiting their exec_die. See should_ingest.
        self._dropped_execs: OrderedDict[str, None] = OrderedDict()

    async def collect(self) -> AsyncIterator[Event]:
        import pathlib

        if not pathlib.Path(self.socket_path).exists():
            logger.warning("docker_socket_not_found", path=self.socket_path)
            return

        logger.info("docker_collector_starting", socket=self.socket_path)

        while True:
            try:
                transport = httpx.AsyncHTTPTransport(uds=self.socket_path)
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://localhost",
                    timeout=None,
                ) as client:
                    async with client.stream(
                        "GET",
                        "/events",
                        params={"since": str(int(datetime.now(UTC).timestamp()))},
                    ) as response:
                        async for line in response.aiter_lines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                                if not should_ingest(
                                    data, self.drop_patterns, self._dropped_execs
                                ):
                                    continue
                                event = parse_docker_event(data)
                                if event:
                                    yield event
                            except json.JSONDecodeError:
                                logger.debug("docker_invalid_json", line=line[:200])
            except httpx.ConnectError:
                logger.warning("docker_connection_lost")
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("docker_collector_error")
                await asyncio.sleep(10)
