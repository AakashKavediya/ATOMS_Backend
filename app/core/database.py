from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
from app.core.config import settings


class MongoDB:
    """Singleton wrapper for MongoDB client and database."""
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None


mongodb = MongoDB()


async def connect_to_mongo() -> None:
    """Called at app startup — verifies MongoDB connection."""
    mongodb.client = AsyncIOMotorClient(
        settings.MONGODB_URI,
        serverSelectionTimeoutMS=5000,
    )
    mongodb.db = mongodb.client[settings.MONGODB_DATABASE]

    # Verify connection with ping
    await mongodb.client.admin.command("ping")
    print(f"✅ Connected to MongoDB: {settings.MONGODB_DATABASE}")


async def close_mongo_connection() -> None:
    """Called at app shutdown."""
    if mongodb.client:
        mongodb.client.close()
        print("🔌 MongoDB connection closed")


def get_database() -> AsyncIOMotorDatabase:
    """FastAPI dependency — returns the database instance."""
    if mongodb.db is None:
        raise RuntimeError("MongoDB not initialized. Did you call connect_to_mongo()?")
    return mongodb.db