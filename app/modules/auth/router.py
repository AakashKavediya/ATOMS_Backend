from fastapi import APIRouter, Depends, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.database import get_database
from app.modules.auth.constants import UserRole
from app.modules.auth.dependencies import get_current_user, require_role
from app.modules.auth.schemas import (
    GoogleSignInRequest,
    RefreshTokenRequest,
    LogoutRequest,
    AssignRoleRequest,
    TokenResponse,
    RefreshResponse,
    MessageResponse,
    SessionResponse,
    UserPublic,
)
from app.modules.auth.service import AuthService


router = APIRouter()


# ==========================================
# Google Sign-In
# ==========================================
@router.post(
    "/google",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Sign in with Google",
)
async def google_sign_in(
    body: GoogleSignInRequest,
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Exchange a Google ID token for our own JWT tokens."""
    service = AuthService(db)
    user_agent = request.headers.get("user-agent")
    ip_address = request.client.host if request.client else None

    access_token, refresh_token, user = await service.sign_in_with_google(
        id_token=body.id_token,
        user_agent=user_agent,
        ip_address=ip_address,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user,
    )


# ==========================================
# Refresh Access Token
# ==========================================
@router.post(
    "/refresh",
    response_model=RefreshResponse,
    summary="Refresh access token",
)
async def refresh_token(
    body: RefreshTokenRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    service = AuthService(db)
    access_token, expires_in = await service.refresh_access_token(body.refresh_token)
    return RefreshResponse(access_token=access_token, expires_in=expires_in)


# ==========================================
# Logout
# ==========================================
@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout (revoke refresh token)",
)
async def logout(
    body: LogoutRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    service = AuthService(db)
    if body.refresh_token:
        await service.logout(body.refresh_token)
    return MessageResponse(message="Logged out successfully")


@router.post(
    "/logout-all",
    response_model=MessageResponse,
    summary="Logout from all devices",
)
async def logout_all(
    current_user: dict = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    service = AuthService(db)
    await service.logout_all(str(current_user["_id"]))
    return MessageResponse(message="Logged out from all devices")


# ==========================================
# Current User
# ==========================================
@router.get(
    "/me",
    response_model=SessionResponse,
    summary="Get current logged-in user",
)
async def get_me(current_user: dict = Depends(get_current_user)):
    return SessionResponse(
        user=UserPublic(
            id=str(current_user["_id"]),
            email=current_user["email"],
            name=current_user.get("name"),
            picture=current_user.get("picture"),
            role=UserRole(current_user["role"]) if current_user.get("role") else None,
            status=current_user.get("status", "PENDING"),
        )
    )


# ==========================================
# Assign Role (Admin / HOD only — for now)
# ==========================================
@router.post(
    "/assign-role",
    response_model=UserPublic,
    summary="Assign role to a user (admin only)",
)
async def assign_role(
    body: AssignRoleRequest,
    current_user: dict = Depends(require_role(UserRole.ADMIN, UserRole.HOD)),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Assign a role to a user by email. Creates user if not exists?"""
    from fastapi import HTTPException
    from app.modules.auth.repository import AuthRepository

    repo = AuthRepository(db)
    user = await repo.get_user_by_email(body.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found. They must sign in with Google first.",
        )

    await repo.update_user_role(str(user["_id"]), body.role)
    user = await repo.get_user_by_id(str(user["_id"]))

    return UserPublic(
        id=str(user["_id"]),
        email=user["email"],
        name=user.get("name"),
        picture=user.get("picture"),
        role=UserRole(user["role"]),
        status=user.get("status", "ACTIVE"),
    )