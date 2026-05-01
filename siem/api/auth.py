import structlog
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from siem.auth import (
    find_user_by_username,
    get_current_user,
    touch_last_login,
    verify_password,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


@router.post("/login")
async def login(req: LoginRequest, request: Request) -> dict:
    user = await find_user_by_username(req.username)
    # Keep the response generic to avoid username enumeration.
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password",
    )
    if user is None or user.status != "active":
        raise unauthorized
    if not verify_password(req.password, user.password_hash):
        logger.info("login_failed", username=req.username)
        raise unauthorized

    await touch_last_login(user)
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = user.role
    logger.info("login_success", username=user.username)
    return {"status": "ok", "user": user.public_dict()}


@router.post("/logout")
async def logout(request: Request) -> dict:
    username = request.session.get("username")
    request.session.clear()
    if username:
        logger.info("logout", username=username)
    return {"status": "ok"}


@router.get("/me")
async def me(request: Request) -> dict:
    user = await get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user.public_dict()
