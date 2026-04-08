import math
from datetime import UTC, datetime, timedelta

import structlog
from elasticsearch import AsyncElasticsearch

from siem.models.alert import Alert
from siem.models.event import EventSeverity

logger = structlog.get_logger()

# How many standard deviations above the mean to trigger
SIGMA_THRESHOLD = 3.0

# Minimum baseline count to consider meaningful (avoid alerting on tiny samples)
MIN_BASELINE_COUNT = 10


async def detect_volume_anomaly(
    es: AsyncElasticsearch,
    baseline_days: int = 7,
    current_window_hours: int = 1,
) -> list[Alert]:
    """Detect anomalous event volume by comparing the last hour to a 7-day rolling baseline.

    For each (source, category) pair, computes hourly mean and stddev over the
    baseline period, then checks if the current hour's count exceeds mean + 3*sigma.
    """
    alerts: list[Alert] = []
    now = datetime.now(UTC)
    baseline_start = (now - timedelta(days=baseline_days)).isoformat()
    current_start = (now - timedelta(hours=current_window_hours)).isoformat()

    # Step 1: Get baseline stats per (source, category) bucket — hourly counts over N days
    baseline_body = {
        "query": {
            "range": {"timestamp": {"gte": baseline_start, "lt": current_start}}
        },
        "size": 0,
        "aggs": {
            "by_source": {
                "terms": {"field": "source", "size": 50},
                "aggs": {
                    "by_category": {
                        "terms": {"field": "category", "size": 20},
                        "aggs": {
                            "hourly": {
                                "date_histogram": {
                                    "field": "timestamp",
                                    "fixed_interval": "1h",
                                }
                            }
                        },
                    }
                },
            }
        },
    }

    try:
        baseline_result = await es.search(index="siem-events-*", body=baseline_body)
    except Exception:
        logger.exception("anomaly_baseline_query_error")
        return alerts

    # Build baseline stats: {(source, category): (mean, stddev)}
    baselines: dict[tuple[str, str], tuple[float, float]] = {}

    for src_bucket in baseline_result["aggregations"]["by_source"]["buckets"]:
        source = src_bucket["key"]
        for cat_bucket in src_bucket["by_category"]["buckets"]:
            category = cat_bucket["key"]
            counts = [b["doc_count"] for b in cat_bucket["hourly"]["buckets"]]
            if len(counts) < MIN_BASELINE_COUNT:
                continue
            mean = sum(counts) / len(counts)
            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            stddev = math.sqrt(variance)
            baselines[(source, category)] = (mean, stddev)

    if not baselines:
        return alerts

    # Step 2: Get current-window counts per (source, category)
    current_body = {
        "query": {"range": {"timestamp": {"gte": current_start}}},
        "size": 0,
        "aggs": {
            "by_source": {
                "terms": {"field": "source", "size": 50},
                "aggs": {
                    "by_category": {
                        "terms": {"field": "category", "size": 20},
                    }
                },
            }
        },
    }

    try:
        current_result = await es.search(index="siem-events-*", body=current_body)
    except Exception:
        logger.exception("anomaly_current_query_error")
        return alerts

    for src_bucket in current_result["aggregations"]["by_source"]["buckets"]:
        source = src_bucket["key"]
        for cat_bucket in src_bucket["by_category"]["buckets"]:
            category = cat_bucket["key"]
            current_count = cat_bucket["doc_count"]
            key = (source, category)

            if key not in baselines:
                continue

            mean, stddev = baselines[key]
            if stddev == 0:
                # Zero variance — alert if current exceeds 2x the mean
                if current_count > mean * 2 and current_count > MIN_BASELINE_COUNT:
                    threshold = mean * 2
                else:
                    continue
            else:
                threshold = mean + SIGMA_THRESHOLD * stddev
                if current_count <= threshold:
                    continue

            sigma_val = (current_count - mean) / stddev if stddev > 0 else float("inf")

            alert = Alert(
                rule_id="anomaly-volume",
                rule_name="Volume Anomaly",
                severity=EventSeverity.HIGH if sigma_val > 5 else EventSeverity.MEDIUM,
                description=(
                    f"Unusual event volume for {source}/{category}: "
                    f"{current_count} events in last {current_window_hours}h "
                    f"(baseline: {mean:.1f} +/- {stddev:.1f}, {sigma_val:.1f} sigma)"
                ),
                context={
                    "source": source,
                    "category": category,
                    "current_count": current_count,
                    "baseline_mean": round(mean, 2),
                    "baseline_stddev": round(stddev, 2),
                    "sigma": round(sigma_val, 2),
                },
            )
            alerts.append(alert)

    return alerts


async def detect_rare_tuples(
    es: AsyncElasticsearch,
    lookback_hours: int = 1,
    baseline_days: int = 7,
) -> list[Alert]:
    """Detect novel (source, category, action) tuples not seen in the baseline period.

    If a combination appears in the last hour but has zero occurrences in the
    prior 7 days, it's flagged as a rare/novel event.
    """
    alerts: list[Alert] = []
    now = datetime.now(UTC)
    current_start = (now - timedelta(hours=lookback_hours)).isoformat()
    baseline_start = (now - timedelta(days=baseline_days)).isoformat()

    # Get (source, category, action) tuples from last hour
    current_body = {
        "query": {"range": {"timestamp": {"gte": current_start}}},
        "size": 0,
        "aggs": {
            "by_source": {
                "terms": {"field": "source", "size": 50},
                "aggs": {
                    "by_category": {
                        "terms": {"field": "category", "size": 20},
                        "aggs": {
                            "by_action": {
                                "terms": {"field": "parsed.action", "size": 50},
                            }
                        },
                    }
                },
            }
        },
    }

    try:
        current_result = await es.search(index="siem-events-*", body=current_body)
    except Exception:
        logger.exception("rare_tuple_current_query_error")
        return alerts

    # Collect current tuples
    current_tuples: list[tuple[str, str, str, int]] = []
    for src_bucket in current_result["aggregations"]["by_source"]["buckets"]:
        source = src_bucket["key"]
        for cat_bucket in src_bucket["by_category"]["buckets"]:
            category = cat_bucket["key"]
            for act_bucket in cat_bucket["by_action"]["buckets"]:
                action = act_bucket["key"]
                count = act_bucket["doc_count"]
                current_tuples.append((source, category, action, count))

    # Check each tuple against baseline
    for source, category, action, count in current_tuples:
        baseline_body = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": baseline_start, "lt": current_start}}},
                        {"term": {"source": source}},
                        {"term": {"category": category}},
                        {"term": {"parsed.action": action}},
                    ]
                }
            },
            "size": 0,
        }

        try:
            baseline_result = await es.search(index="siem-events-*", body=baseline_body)
            baseline_count = baseline_result["hits"]["total"]["value"]
        except Exception:
            continue

        if baseline_count == 0:
            alert = Alert(
                rule_id="anomaly-rare-tuple",
                rule_name="Rare Event Detected",
                severity=EventSeverity.MEDIUM,
                description=(
                    f"Novel event type detected: {source}/{category}/{action} "
                    f"({count} occurrences in last {lookback_hours}h, "
                    f"never seen in prior {baseline_days} days)"
                ),
                context={
                    "source": source,
                    "category": category,
                    "action": action,
                    "current_count": count,
                    "baseline_days": baseline_days,
                },
            )
            alerts.append(alert)

    return alerts
