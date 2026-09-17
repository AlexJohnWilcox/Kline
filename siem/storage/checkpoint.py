from datetime import UTC, datetime

import structlog
from elasticsearch import NotFoundError

logger = structlog.get_logger()

STATE_INDEX = "siem-state"


async def get_checkpoint(es, name: str) -> int:
    """Read a collector's cursor. Absent means 'never run', which is 0."""
    try:
        doc = await es.get(index=STATE_INDEX, id=name)
    except NotFoundError:
        return 0
    except Exception:
        logger.exception("checkpoint_read_error", name=name)
        return 0
    return int(doc["_source"].get("value", 0))


async def set_checkpoint(es, name: str, value: int) -> None:
    """Persist a collector's cursor so it survives restart and poweroff."""
    await es.index(
        index=STATE_INDEX,
        id=name,
        document={"value": value, "updated_at": datetime.now(UTC).isoformat()},
        refresh=True,
    )
