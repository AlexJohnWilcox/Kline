import abc
import asyncio
from typing import AsyncIterator

import structlog

from siem.models.event import Event

logger = structlog.get_logger()


class BaseCollector(abc.ABC):
    """Abstract base class for log collectors."""

    def __init__(self, name: str):
        self.name = name
        self._running = False
        self._task: asyncio.Task | None = None
        self._event_count = 0
        self._blind_reason: str | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def blind_reason(self) -> str | None:
        return self._blind_reason

    @property
    def health(self) -> str:
        """ok, blind, or stopped.

        "blind" means the collector is configured to read something that is
        not there. It is distinct from "stopped" because stopped is what a
        cancelled collector looks like at shutdown, and blind is a
        misconfiguration nobody will notice otherwise: the collector reports
        no events, which is exactly what a quiet source reports.
        """
        if self._blind_reason:
            return "blind"
        return "ok" if self._running else "stopped"

    def mark_blind(self, reason: str) -> None:
        """Record that this collector has nothing it can read, and why."""
        self._blind_reason = reason
        logger.warning("collector_blind", name=self.name, reason=reason)

    @abc.abstractmethod
    async def collect(self) -> AsyncIterator[Event]:
        """Yield normalized events from the log source. Runs continuously."""
        ...

    async def start(self, event_queue: asyncio.Queue[Event]) -> None:
        """Start collecting events and pushing them to the queue."""
        self._running = True
        logger.info("collector_started", name=self.name)
        try:
            async for event in self.collect():
                await event_queue.put(event)
                self._event_count += 1
        except asyncio.CancelledError:
            logger.info("collector_stopped", name=self.name)
        except Exception:
            logger.exception("collector_error", name=self.name)
        finally:
            self._running = False

    def status(self) -> dict:
        return {
            "name": self.name,
            "running": self._running,
            "event_count": self._event_count,
            "health": self.health,
            "blind_reason": self._blind_reason,
        }
