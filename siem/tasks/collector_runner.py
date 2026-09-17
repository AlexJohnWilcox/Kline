import asyncio

import structlog

from siem.collectors.base import BaseCollector
from siem.models.event import Event
from siem.storage.es_client import get_es_client
from siem.storage.queries import index_events_bulk

logger = structlog.get_logger()


class CollectorRunner:
    """Manages all collectors and indexes their events into Elasticsearch."""

    def __init__(self):
        self.collectors: list[BaseCollector] = []
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._tasks: list[asyncio.Task] = []
        self._indexer_task: asyncio.Task | None = None

    def register(self, collector: BaseCollector) -> None:
        self.collectors.append(collector)

    async def start(self) -> None:
        """Start all collectors and the event indexer."""
        # Start the bulk indexer
        self._indexer_task = asyncio.create_task(self._bulk_indexer())

        # Start each collector
        for collector in self.collectors:
            task = asyncio.create_task(collector.start(self._queue))
            self._tasks.append(task)

        logger.info("collector_runner_started", count=len(self.collectors))

    async def stop(self) -> None:
        """Stop all collectors and the indexer."""
        for task in self._tasks:
            task.cancel()
        if self._indexer_task:
            self._indexer_task.cancel()

        await asyncio.gather(*self._tasks, self._indexer_task, return_exceptions=True)
        self._tasks.clear()
        logger.info("collector_runner_stopped")

    async def _bulk_indexer(self) -> None:
        """Drain the event queue and bulk-index into Elasticsearch."""
        es = await get_es_client()
        batch: list[Event] = []

        while True:
            try:
                # Wait for first event
                event = await asyncio.wait_for(self._queue.get(), timeout=5.0)
                batch.append(event)

                # Drain remaining available events (up to batch size)
                while len(batch) < 100:
                    try:
                        event = self._queue.get_nowait()
                        batch.append(event)
                    except asyncio.QueueEmpty:
                        break

                # Index the batch
                count = await index_events_bulk(es, batch)
                self._log_indexed("events_indexed", count, len(batch))
                batch.clear()

            except asyncio.TimeoutError:
                # Flush any partial batch on timeout
                if batch:
                    count = await index_events_bulk(es, batch)
                    self._log_indexed("events_indexed_flush", count, len(batch))
                    batch.clear()
            except asyncio.CancelledError:
                # Final flush on shutdown
                if batch:
                    await index_events_bulk(es, batch)
                raise
            except Exception:
                # The batch is unrecoverable and is dropped. Say how much was
                # lost: at ~55k events/day this is the one place data leaves
                # the pipeline for good, and it must not be a bare line.
                logger.exception("indexer_error", dropped=len(batch))
                if batch:
                    logger.warning("events_dropped", count=len(batch))
                batch.clear()

    @staticmethod
    def _log_indexed(event: str, count: int, attempted: int) -> None:
        """Log a bulk result, loudly when Elasticsearch rejected part of it.

        index_events_bulk returns a reduced count on a partial failure rather
        than raising. Logged only at debug, a steady trickle of rejected
        documents -- a mapping conflict, or 429s under load -- is invisible.
        """
        if count < attempted:
            logger.warning(
                "events_index_partial_failure",
                indexed=count,
                attempted=attempted,
                failed=attempted - count,
            )
        else:
            logger.debug(event, count=count)

    def status(self) -> list[dict]:
        return [c.status() for c in self.collectors]
