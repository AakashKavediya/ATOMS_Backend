from typing import Dict, Any
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi import HTTPException, status

from app.core.config import settings


def verify_google_id_token(token: str) -> Dict[str, Any]:
    """
    Verify a Google ID token issued by Google Sign-In.

    Returns the decoded payload containing:
    - sub (Google user ID)
    - email
    - email_verified
    - name
    - picture
    - given_name, family_name
    """
    try:
        payload = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            settings.GOOGLE_CLIENT_ID,
        )
        return payload
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google token: {str(e)}",
        )


def check_email_domain_allowed(email: str) -> bool:
    """Check if email domain is allowed (if restriction is enabled)."""
    if not settings.ALLOWED_EMAIL_DOMAINS:
        return True
    domain = email.split("@")[-1].lower()
    return domain in [d.lower() for d in settings.ALLOWED_EMAIL_DOMAINS]