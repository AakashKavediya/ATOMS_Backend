from enum import Enum


class UserRole(str, Enum):
    HOD = "HOD"
    TEACHER = "TEACHER"
    STUDENT = "STUDENT"
    ADMIN = "ADMIN"


class UserStatus(str, Enum):
    PENDING = "PENDING"     # Signed up via Google, no role assigned yet
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


# JWT token type
TOKEN_TYPE_ACCESS = "access"

# Error messages
ERROR_INVALID_TOKEN = "Invalid or expired token"
ERROR_USER_NOT_FOUND = "User not found"
ERROR_EMAIL_NOT_ALLOWED = "Email domain not allowed"
ERROR_ROLE_NOT_ASSIGNED = "Role not assigned. Please contact admin."
ERROR_USER_SUSPENDED = "Your account has been suspended"
ERROR_INVALID_REFRESH_TOKEN = "Invalid or expired refresh token"