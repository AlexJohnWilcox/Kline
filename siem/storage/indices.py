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
                "parsed": {
                    "dynamic": True,
                    "properties": {
                        "domain": {"type": "keyword"},
                        "client": {"type": "keyword"},
                        "status": {"type": "integer"},
                        "blocked": {"type": "boolean"},
                        "reply_type": {"type": "integer"},
                        "nxdomain": {"type": "boolean"},
                        "query_type": {"type": "keyword"},
                        "upstream": {"type": "keyword"},
                        "ftl_rowid": {"type": "long"},
                        "process": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "src_ip": {"type": "ip"},
                        "src_port": {"type": "integer"},
                        "dst_port": {"type": "integer"},
                        "auth_method": {"type": "keyword"},
                        "facility": {"type": "keyword"},
                        "in_iface": {"type": "keyword"},
                        "out_iface": {"type": "keyword"},
                        "pid": {"type": "long"},
                    },
                },
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
                "resolution_reason": {"type": "text"},
                "context": {
                    # Other rules put their own shapes in here, so dynamic
                    # stays on. hosts is declared because the device panel
                    # queries it: left dynamic it becomes analysed text, and a
                    # term query would match only by the accident that the
                    # standard analyser does not split a dotted IPv4.
                    "dynamic": True,
                    "properties": {
                        # text + keyword mirrors what dynamic mapping already
                        # produced, deliberately. The device panel runs a terms
                        # aggregation, and an aggregation - unlike a term query
                        # - refuses an analysed text field outright ("Fielddata
                        # is disabled"). It must aggregate on .keyword, so that
                        # subfield has to exist on new indices as well as the
                        # ones already written.
                        "hosts": {
                            "type": "text",
                            "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                        },
                        "event_count": {"type": "long"},
                    },
                },
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

STATE_INDEX_TEMPLATE = {
    "index_patterns": ["siem-state"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "value": {"type": "long"},
                "updated_at": {"type": "date"},
            }
        },
    },
}


DEVICE_INDEX_TEMPLATE = {
    "index_patterns": ["siem-devices"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        # The map is one small object of arbitrary keys. Indexing every
        # address as a field would be pointless and would grow the mapping
        # every time a device appears, so it is stored and not indexed.
        # fetched_at is a sibling of names, not a field inside it: "enabled":
        # False switches off indexing for everything under names, so a date
        # kept in there could never be searched or aggregated. Here it is an
        # ordinary indexed date, and _source returns it either way.
        "mappings": {
            "properties": {
                "names": {"type": "object", "enabled": False},
                "fetched_at": {"type": "date"},
            }
        },
    },
}


SEEN_INDEX_TEMPLATE = {
    "index_patterns": ["siem-seen"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "values": {"type": "keyword"},
                "updated_at": {"type": "date"},
            }
        },
    },
}


def get_event_index(when: datetime | None = None) -> str:
    """Event indices are daily, so a 30-day retention window can be expressed."""
    when = when or datetime.now(UTC)
    return f"siem-events-{when.strftime('%Y.%m.%d')}"


def get_alert_index(when: datetime | None = None) -> str:
    """Alert indices stay monthly — they live a year and are small."""
    when = when or datetime.now(UTC)
    return f"siem-alerts-{when.strftime('%Y.%m')}"


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

    await es.indices.put_index_template(
        name="siem-state",
        body=STATE_INDEX_TEMPLATE,
    )
    logger.info("index_template_created", name="siem-state")

    await es.indices.put_index_template(
        name="siem-devices",
        body=DEVICE_INDEX_TEMPLATE,
    )
    logger.info("index_template_created", name="siem-devices")

    await es.indices.put_index_template(
        name="siem-seen",
        body=SEEN_INDEX_TEMPLATE,
    )
    logger.info("index_template_created", name="siem-seen")
