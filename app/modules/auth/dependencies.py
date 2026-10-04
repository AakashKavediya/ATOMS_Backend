from typing import Optional
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.database import get_database
from app.core.security import decode_access_token
from app.modules.auth.constants import (
    ERROR_INVALID_TOKEN,
    ERROR_USER_NOT_FOUND,
    UserRole,
)
from app.modules.auth.repository import AuthRepository
from app.modules.auth.schemas import UserPublic
from app.modules.auth.constants import UserStatus


# Bearer token extractor
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict:
    """Extract user from Bearer token in Authorization header."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        payload = decode_access_token(token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{ERROR_INVALID_TOKEN}: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_INVALID_TOKEN,
            headers={"WWW-Authenticate": "Bearer"},
        )

    repo = AuthRepository(db)
    user = await repo.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_USER_NOT_FOUND,
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    return user


def require_role(*allowed_roles: UserRole):
    """Factory that returns a dependency enforcing role-based access."""
    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = current_user.get("role")
        if not user_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role not assigned",
            )
        if UserRole(user_role) not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {[r.value for r in allowed_roles]}",
            )
        return current_user
    return role_checker


# Convenience dependencies
require_hod = require_role(UserRole.HOD)
require_teacher = require_role(UserRole.TEACHER)
require_student = require_role(UserRole.STUDENT)
require_any_staff = require_role(UserRole.HOD, UserRole.TEACHER, UserRole.ADMIN)