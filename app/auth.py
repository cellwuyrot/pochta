from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import User

serializer = URLSafeTimedSerializer(settings.secret_key)
SESSION_COOKIE = "admin_session"
SESSION_MAX_AGE = 86400 * 7  # 7 days


def create_session_token(username: str, role: str = "admin") -> str:
    return serializer.dumps({"user": username, "role": role})


def verify_session_token(token: str) -> dict | None:
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data
    except (BadSignature, SignatureExpired):
        return None


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Return the current logged-in User object."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    data = verify_session_token(token)
    if not data or "user" not in data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    user = (
        await db.execute(select(User).where(User.username == data["user"], User.is_active.is_(True)))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    request.state.user_role = user.role
    return user


async def get_current_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> str:
    """Admin-only guard retaining the historical username return type."""
    user = await require_admin(request, db)
    request.state.user_role = user.role
    return user.username


async def require_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Require admin role."""
    user = await get_current_user(request, db)
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    request.state.user_role = user.role
    return user
