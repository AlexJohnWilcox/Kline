import asyncio
import json
import re
import socket
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


def _severity_for_action(action: str) -> EventSeverity:
    """Map Docker event actions to severity."""
    high = {"die", "kill", "oom", "destroy", "pause"}
    medium = {"stop", "restart", "update", "rename", "exec_create", "exec_start"}
    if action in high:
        return EventSeverity.HIGH
    if action in medium:
        return EventSeverity.MEDIUM
    return EventSeverity.LOW


def _category_for_type(event_type: str) -> EventCategory:
    """Map Docker event types to categories."""
    if event_type == "network":
        return EventCategory.NETWORK
    return EventCategory.APPLICATION


def parse_docker_event(data: dict) -> Event | None:
    """Parse a Docker API event into a SIEM Event."""
    status = data.get("status") or data.get("Action", "")
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

    severity = _severity_for_action(status)

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

    def __init__(self, socket_path: str = DOCKER_SOCKET):
        super().__init__(name="docker")
        self.socket_path = socket_path

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
