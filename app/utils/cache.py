"""Optional Redis cache. A no-op unless REDIS_URL is configured; never raises (cache failure = cache miss)."""
import json
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("app.cache")
_client: Any = None
_initialised = False


def _get_client():
    global _client, _initialised
    if _initialised:
        return _client
    _initialised = True
    if settings.REDIS_URL:
        try:
            import redis

            _client = redis.Redis.from_url(settings.REDIS_URL, socket_timeout=1, decode_responses=True)
        except Exception:  # pragma: no cover - depends on environment
            logger.warning("redis unavailable; caching disabled", exc_info=True)
            _client = None
    return _client


def set_client(client: Any) -> None:
    """Inject a client (used by tests)."""
    global _client, _initialised
    _client, _initialised = client, True


def cache_get(key: str) -> Any | None:
    client = _get_client()
    if client is None:
        return None
    try:
        raw = client.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        logger.warning("cache get failed", extra={"cache_key": key})
        return None


def cache_set(key: str, value: Any, ttl_seconds: int) -> None:
    client = _get_client()
    if client is None or ttl_seconds <= 0:
        return
    try:
        client.setex(key, ttl_seconds, json.dumps(value, default=str))
    except Exception:
        logger.warning("cache set failed", extra={"cache_key": key})


def cache_delete_prefix(prefix: str) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        for key in client.scan_iter(match=f"{prefix}*"):
            client.delete(key)
    except Exception:
        logger.warning("cache invalidation failed", extra={"cache_prefix": prefix})
