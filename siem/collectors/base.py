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

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def event_count(self) -> int:
        return self._event_count

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
        }
