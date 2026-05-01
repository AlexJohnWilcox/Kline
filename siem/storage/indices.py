from datetime import UTC, datetime

import structlog
from elasticsearch import AsyncElasticsearch

logger = structlog.get_logger()

EVENT_INDEX_TEMPLATE = {
    "index_patterns": ["siem-events-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
        },
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "source": {"type": "keyword"},
                "host": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "category": {"type": "keyword"},
                "message": {"type": "text"},
                "tags": {"type": "keyword"},
                "raw": {"type": "text", "index": False},
            }
        },
    },
}

ALERT_INDEX_TEMPLATE = {
    "index_patterns": ["siem-alerts-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "rule_id": {"type": "keyword"},
                "rule_name": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "description": {"type": "text"},
                "matched_events": {"type": "keyword"},
                "ai_explanation": {"type": "text"},
                "status": {"type": "keyword"},
            }
        },
    },
}

SUPPRESSION_INDEX_TEMPLATE = {
    "index_patterns": ["siem-suppressions"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "created_at": {"type": "date"},
                "expires_at": {"type": "date"},
                "rule_id": {"type": "keyword"},
                "reason": {"type": "text"},
                "match_fields": {"type": "object", "dynamic": True},
                "source_alert_id": {"type": "keyword"},
                "status": {"type": "keyword"},
            }
        },
    },
}

USER_INDEX_TEMPLATE = {
    "index_patterns": ["siem-users"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "username": {"type": "keyword"},
                "password_hash": {"type": "keyword", "index": False},
                "role": {"type": "keyword"},
                "status": {"type": "keyword"},
                "created_at": {"type": "date"},
                "last_login": {"type": "date"},
            }
        },
    },
}


def get_event_index() -> str:
    """Get the current month's event index name."""
    return f"siem-events-{datetime.now(UTC).strftime('%Y.%m')}"


def get_alert_index() -> str:
    """Get the current month's alert index name."""
    return f"siem-alerts-{datetime.now(UTC).strftime('%Y.%m')}"


async def setup_indices(es: AsyncElasticsearch) -> None:
    """Create index templates if they don't exist."""
    await es.indices.put_index_template(
        name="siem-events",
        body=EVENT_INDEX_TEMPLATE,
    )
    logger.info("index_template_created", name="siem-events")

    await es.indices.put_index_template(
        name="siem-alerts",
        body=ALERT_INDEX_TEMPLATE,
    )
    logger.info("index_template_created", name="siem-alerts")

    await es.indices.put_index_template(
        name="siem-suppressions",
        body=SUPPRESSION_INDEX_TEMPLATE,
    )
    logger.info("index_template_created", name="siem-suppressions")

    await es.indices.put_index_template(
        name="siem-users",
        body=USER_INDEX_TEMPLATE,
    )
    logger.info("index_template_created", name="siem-users")
