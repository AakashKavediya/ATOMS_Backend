from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    # App
    APP_NAME: str = "ATOMS Backend"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # MongoDB
    MONGODB_URI: str
    MONGODB_DATABASE: str

    # JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Google OAuth
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str

    # Frontend / CORS
    FRONTEND_URL: str = "http://localhost:3000"
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # Optional
    ALLOWED_EMAIL_DOMAINS: List[str] = []

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()  # type: ignore[call-arg]