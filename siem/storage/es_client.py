import structlog
from elasticsearch import AsyncElasticsearch

from config.settings import settings

logger = structlog.get_logger()

_client: AsyncElasticsearch | None = None


async def get_es_client() -> AsyncElasticsearch:
    """Get or create the async Elasticsearch client singleton."""
    global _client
    if _client is None:
        _client = AsyncElasticsearch(
            hosts=[settings.es_url],
            request_timeout=30,
        )
        info = await _client.info()
        logger.info(
            "elasticsearch_connected",
            version=info["version"]["number"],
            cluster=info["cluster_name"],
        )
    return _client


async def close_es_client() -> None:
    """Close the Elasticsearch client."""
    global _client
    if _client is not None:
        await _client.close()
        _client = None
        logger.info("elasticsearch_disconnected")
