from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
from app.modules.auth.constants import UserRole, UserStatus


# ==========================================
# Request Schemas
# ==========================================
class GoogleSignInRequest(BaseModel):
    """Frontend sends the Google ID token after successful sign-in."""
    id_token: str = Field(..., description="Google ID token from frontend")


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class AssignRoleRequest(BaseModel):
    email: EmailStr
    role: UserRole


# ==========================================
# Response Schemas
# ==========================================
class UserPublic(BaseModel):
    """Public user object — safe to expose to frontend."""
    id: str
    email: EmailStr
    name: Optional[str] = None
    picture: Optional[str] = None
    role: Optional[UserRole] = None
    status: UserStatus


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserPublic


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MessageResponse(BaseModel):
    message: str
    success: bool = True


class SessionResponse(BaseModel):
    """Returned by /auth/me — current logged-in user."""
    user: UserPublic