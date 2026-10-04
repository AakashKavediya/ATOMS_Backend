from fastapi import APIRouter
from app.modules.auth.router import router as auth_router


api_router = APIRouter()


@api_router.get("/ping", tags=["Health"])
async def ping():
    return {"message": "pong"}


# Auth routes
api_router.include_router(auth_router, prefix="/auth", tags=["Auth"])