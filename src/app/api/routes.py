"""
Phase 1: Simple routes - just imports the auth routes, no complex logic.
"""

from fastapi import APIRouter

# Import the mock auth routes
from app.api.auth_routes import router as auth_router

# Create main router
router = APIRouter()

# Include auth routes
router.include_router(auth_router, prefix="/v1")

@router.get("/")
async def api_root():
    return {
        "message": "Buildvilds API - Phase 1",
        "version": "1.0.0",
        "endpoints": [
            "/v1/auth/signup",
            "/v1/auth/verify-email", 
            "/v1/auth/signin",
            "/v1/auth/users",
            "/v1/auth/reset"
        ]
    }