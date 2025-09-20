"""
Phase 3: Complete FastAPI app with JWT tokens and bcrypt security.
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.core.database import connect_to_database, close_database_connection
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Buildvilds Backend API - Phase 3 Complete",
    description="""
    ## 🔐 Phase 3: JWT Authentication System
    
    ### New Features:
    * **🔐 JWT Tokens**: Real JWT access tokens for authentication
    * **🔒 Bcrypt Security**: Secure password hashing with bcrypt
    * **🛡️ Protected Routes**: Endpoints that require JWT authentication
    * **✅ Password Validation**: Strong password requirements
    * **🔑 Token-based Access**: Use Bearer tokens for authenticated requests
    
    ### Authentication Flow:
    1. **Sign Up** → Creates account with bcrypt password hashing
    2. **Verify Email** → Validates email with OTP
    3. **Sign In** → Returns JWT access token
    4. **Protected Access** → Use `Authorization: Bearer <token>` header
    
    ### Protected Endpoints:
    * `GET /auth/me` - Get current user info (requires JWT)
    * `POST /auth/test-protected` - Test JWT authentication
    """,
    version="3.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error in {request.method} {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Unexpected error: {str(exc)}"}
    )

@app.on_event("startup")
async def startup_event():
    """Initialize database connection."""
    logger.info("🚀 Starting Buildvilds Backend API - Phase 3 (JWT + Bcrypt)...")
    try:
        await connect_to_database()
        logger.info("✅ Phase 3 application started with JWT authentication!")
    except Exception as e:
        logger.error(f"❌ Failed to start with database: {e}")
        logger.info("⚠️  Continuing without database...")

@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection."""
    try:
        await close_database_connection()
        logger.info("✅ Application shutdown completed")
    except Exception as e:
        logger.error(f"❌ Error during shutdown: {e}")

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with Phase 3 complete info."""
    return {
        "message": "🔐 Buildvilds Backend API - Phase 3 JWT Complete!",
        "version": "3.0.0",
        "phase": "Phase 3 - JWT Authentication System",
        "status": "Production Ready Security",
        "features": [
            "✅ JWT access tokens with 1-hour expiry",
            "✅ Bcrypt password hashing (secure)",
            "✅ Password strength validation",
            "✅ Protected endpoints with Bearer auth",
            "✅ MongoDB database storage",
            "✅ OTP email verification system"
        ],
        "docs": "/docs",
        "authentication_flow": [
            "1. POST /api/v1/auth/signup - Register with strong password",
            "2. POST /api/v1/auth/verify-email - Verify with OTP",
            "3. POST /api/v1/auth/signin - Get JWT token",
            "4. Use Authorization: Bearer <token> for protected routes"
        ],
        "protected_endpoints": [
            "🔒 GET /api/v1/auth/me - Current user info",
            "🔒 POST /api/v1/auth/test-protected - Test JWT auth"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check with Phase 3 status."""
    from app.core.database import db_client
    
    db_status = "connected" if db_client else "disconnected"
    
    return {
        "status": "healthy",
        "service": "buildvilds-backend",
        "version": "3.0.0",
        "phase": "Phase 3 - JWT Complete",
        "components": {
            "database": db_status,
            "jwt_service": "ready",
            "password_service": "ready (bcrypt)",
            "authentication": "jwt_enabled"
        }
    }

# Include API routes
app.include_router(api_router, prefix="/api")