from datetime import datetime, timezone
from typing import Optional
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.collections import Collections
from app.modules.auth.constants import UserRole, UserStatus


class AuthRepository:
    """All database queries related to auth."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.users = db[Collections.USERS]
        self.refresh_tokens = db[Collections.REFRESH_TOKENS]

    # ==========================================
    # Users
    # ==========================================
    async def get_user_by_id(self, user_id: str) -> Optional[dict]:
        if not ObjectId.is_valid(user_id):
            return None
        return await self.users.find_one({"_id": ObjectId(user_id)})

    async def get_user_by_email(self, email: str) -> Optional[dict]:
        return await self.users.find_one({"email": email.lower()})

    async def get_user_by_google_id(self, google_id: str) -> Optional[dict]:
        return await self.users.find_one({"google_id": google_id})

    async def create_user(
        self,
        email: str,
        name: Optional[str],
        picture: Optional[str],
        google_id: str,
        role: Optional[UserRole] = None,
        status: UserStatus = UserStatus.PENDING,
    ) -> dict:
        now = datetime.now(timezone.utc)
        doc = {
            "email": email.lower(),
            "name": name,
            "picture": picture,
            "google_id": google_id,
            "role": role.value if role else None,
            "status": status.value,
            "is_active": True,
            "last_login_at": now,
            "created_at": now,
            "updated_at": now,
        }
        result = await self.users.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def update_last_login(self, user_id: str) -> None:
        await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"last_login_at": datetime.now(timezone.utc)}},
        )

    async def update_user(self, user_id: str, updates: dict) -> None:
        updates["updated_at"] = datetime.now(timezone.utc)
        await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": updates},
        )

    async def update_user_role(self, user_id: str, role: UserRole) -> None:
        await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "role": role.value,
                    "status": UserStatus.ACTIVE.value,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

    async def list_users(self, skip: int = 0, limit: int = 50) -> list[dict]:
        cursor = self.users.find().skip(skip).limit(limit).sort("created_at", -1)
        return await cursor.to_list(length=limit)

    # ==========================================
    # Refresh Tokens
    # ==========================================
    async def create_refresh_token(
        self,
        user_id: str,
        token_hash: str,
        expires_at: datetime,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> dict:
        doc = {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": expires_at,
            "revoked": False,
            "user_agent": user_agent,
            "ip_address": ip_address,
            "created_at": datetime.now(timezone.utc),
        }
        result = await self.refresh_tokens.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def get_refresh_token(self, token_hash: str) -> Optional[dict]:
        return await self.refresh_tokens.find_one({
            "token_hash": token_hash,
            "revoked": False,
        })

    async def revoke_refresh_token(self, token_hash: str) -> None:
        await self.refresh_tokens.update_one(
            {"token_hash": token_hash},
            {"$set": {"revoked": True}},
        )

    async def revoke_all_user_tokens(self, user_id: str) -> None:
        await self.refresh_tokens.update_many(
            {"user_id": user_id, "revoked": False},
            {"$set": {"revoked": True}},
        )