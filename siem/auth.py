from datetime import UTC, datetime

import bcrypt
import structlog
from elasticsearch import NotFoundError
from fastapi import HTTPException, Request, status

from siem.models.user import User
from siem.storage.es_client import get_es_client

logger = structlog.get_logger()

USER_INDEX = "siem-users"
_BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]  # bcrypt max input
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8")[:72],
            password_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


async def find_user_by_username(username: str) -> User | None:
    es = await get_es_client()
    try:
        result = await es.search(
            index=USER_INDEX,
            body={"query": {"term": {"username": username}}, "size": 1},
        )
    except Exception as exc:
        logger.warning("user_lookup_failed", username=username, error=str(exc))
        return None
    hits = result["hits"]["hits"]
    if not hits:
        return None
    return User.from_es_hit(hits[0])


async def find_user_by_id(user_id: str) -> User | None:
    es = await get_es_client()
    try:
        result = await es.get(index=USER_INDEX, id=user_id)
    except NotFoundError:
        return None
    except Exception as exc:
        logger.warning("user_get_failed", user_id=user_id, error=str(exc))
        return None
    source = result["_source"]
    source.setdefault("id", result["_id"])
    return User(**source)


async def save_user(user: User) -> None:
    es = await get_es_client()
    await es.index(
        index=USER_INDEX,
        id=user.id,
        document=user.to_es_doc(),
        refresh="wait_for",
    )


async def seed_admin_if_missing(username: str, password: str) -> None:
    existing = await find_user_by_username(username)
    if existing:
        logger.info("admin_user_present", username=username)
        return
    user = User(
        username=username,
        password_hash=hash_password(password),
        role="admin",
    )
    await save_user(user)
    logger.info("admin_user_seeded", username=username)


async def touch_last_login(user: User) -> None:
    user.last_login = datetime.now(UTC)
    await save_user(user)


async def get_current_user(request: Request) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = await find_user_by_id(user_id)
    if user is None or user.status != "active":
        return None
    return user


async def require_user(request: Request) -> User:
    user = await get_current_user(request)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user
