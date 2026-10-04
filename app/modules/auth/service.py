from datetime import datetime, timezone
from typing import Optional, Tuple
import hashlib
import secrets

from bson import ObjectId
from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.google_auth import verify_google_id_token, check_email_domain_allowed
from app.core.security import create_access_token
from app.modules.auth.constants import (
    ERROR_EMAIL_NOT_ALLOWED,
    ERROR_INVALID_REFRESH_TOKEN,
    ERROR_ROLE_NOT_ASSIGNED,
    ERROR_USER_NOT_FOUND,
    ERROR_USER_SUSPENDED,
    UserRole,
    UserStatus,
)
from app.modules.auth.repository import AuthRepository
from app.modules.auth.schemas import UserPublic


# ==========================================
# Refresh token helpers
# ==========================================
def _generate_refresh_token() -> str:
    """Cryptographically secure random string."""
    return secrets.token_urlsafe(64)


def _hash_refresh_token(token: str) -> str:
    """SHA-256 hash for storage (token is random, so SHA-256 is fine)."""
    return hashlib.sha256(token.encode()).hexdigest()


# ==========================================
# User → Public converter
# ==========================================
def _to_public(user: dict) -> UserPublic:
    return UserPublic(
        id=str(user["_id"]),
        email=user["email"],
        name=user.get("name"),
        picture=user.get("picture"),
        role=UserRole(user["role"]) if user.get("role") else None,
        status=UserStatus(user.get("status", "PENDING")),
    )


# ==========================================
# Auth Service
# ==========================================
class AuthService:

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.repo = AuthRepository(db)

    # ------------------------------------------
    # Google Sign-In
    # ------------------------------------------
    async def sign_in_with_google(
        self,
        id_token: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Tuple[str, str, UserPublic]:
        """
        1. Verify Google ID token
        2. Find or create user in MongoDB
        3. Issue access + refresh tokens
        """
        # 1. Verify with Google
        payload = verify_google_id_token(id_token)

        email = payload.get("email")
        name = payload.get("name")
        picture = payload.get("picture")
        google_id = payload.get("sub")
        email_verified = payload.get("email_verified", False)

        if not email or not google_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google token missing email or sub",
            )

        if not email_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google email not verified",
            )

        if not check_email_domain_allowed(email):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ERROR_EMAIL_NOT_ALLOWED,
            )

        # 2. Find existing user (by google_id OR email)
        user = await self.repo.get_user_by_google_id(google_id)
        if not user:
            user = await self.repo.get_user_by_email(email)

        if user:
            # Update Google profile fields + last login
            await self.repo.update_user(
                str(user["_id"]),
                {
                    "name": name or user.get("name"),
                    "picture": picture or user.get("picture"),
                    "google_id": google_id,
                    "last_login_at": datetime.now(timezone.utc),
                },
            )
            user = await self.repo.get_user_by_id(str(user["_id"]))
        else:
            # Create new user (PENDING until role assigned)
            user = await self.repo.create_user(
                email=email,
                name=name,
                picture=picture,
                google_id=google_id,
                role=None,
                status=UserStatus.PENDING,
            )

        if not user.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ERROR_USER_SUSPENDED,
            )

        # 3. Issue tokens
        access_token = create_access_token(
            str(user["_id"]),
            user.get("role"),
        )
        refresh_token = _generate_refresh_token()
        expires_at = datetime.now(timezone.utc).replace(microsecond=0)
        from datetime import timedelta
        expires_at = expires_at + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        await self.repo.create_refresh_token(
            user_id=str(user["_id"]),
            token_hash=_hash_refresh_token(refresh_token),
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        return access_token, refresh_token, _to_public(user)

    # ------------------------------------------
    # Refresh Access Token
    # ------------------------------------------
    async def refresh_access_token(self, refresh_token: str) -> Tuple[str, int]:
        token_hash = _hash_refresh_token(refresh_token)
        rt = await self.repo.get_refresh_token(token_hash)

        if not rt:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_INVALID_REFRESH_TOKEN,
            )

        # Check expiry (Mongo stores tz-aware datetime)
        expires_at = rt["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await self.repo.revoke_refresh_token(token_hash)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_INVALID_REFRESH_TOKEN,
            )

        user = await self.repo.get_user_by_id(rt["user_id"])
        if not user or not user.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_USER_NOT_FOUND,
            )

        access_token = create_access_token(
            str(user["_id"]),
            user.get("role"),
        )
        return access_token, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # ------------------------------------------
    # Logout
    # ------------------------------------------
    async def logout(self, refresh_token: str) -> None:
        token_hash = _hash_refresh_token(refresh_token)
        await self.repo.revoke_refresh_token(token_hash)

    async def logout_all(self, user_id: str) -> None:
        await self.repo.revoke_all_user_tokens(user_id)

    # ------------------------------------------
    # Current User
    # ------------------------------------------
    async def get_current_user(self, user_id: str) -> dict:
        user = await self.repo.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_USER_NOT_FOUND,
            )
        return user