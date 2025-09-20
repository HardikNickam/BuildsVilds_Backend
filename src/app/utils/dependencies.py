"""
FastAPI dependencies for authentication, rate limiting, and request validation.
These functions are used to protect routes and validate requests.
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.services.jwt_service import jwt_service
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.connectors.redis_client import redis_service
from app.core.config import settings
from typing import Optional
import logging
from datetime import datetime, timedelta, UTC

# Set up logging
logger = logging.getLogger(__name__)

# Security scheme for JWT authentication
security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> User:
    """
    Dependency to get the current authenticated user from JWT token.
    This is used to protect routes that require authentication.
    
    Args:
        credentials: HTTP Bearer token from Authorization header
        
    Returns:
        User object if token is valid
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    # Check if token is provided
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify the token
    token_payload = jwt_service.verify_access_token(credentials.credentials)
    
    if not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    user_id = token_payload.get("sub")
    user = await User.get(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )
    
    # Check if account is locked
    if user.is_account_locked():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to multiple failed login attempts",
        )
    
    return user

async def get_current_verified_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to get current user with verified email.
    Used for routes that require email verification.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User object if email is verified
        
    Raises:
        HTTPException: If email is not verified
    """
    if not current_user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required",
        )
    
    return current_user

async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """
    Optional dependency to get current user.
    Returns None if no token provided or token is invalid.
    Used for routes that work with or without authentication.
    
    Args:
        credentials: Optional HTTP Bearer token
        
    Returns:
        User object if authenticated, None otherwise
    """
    if not credentials:
        return None
    
    try:
        # Verify the token
        token_payload = jwt_service.verify_access_token(credentials.credentials)
        
        if not token_payload:
            return None
        
        # Get user from database
        user_id = token_payload.get("sub")
        user = await User.get(user_id)
        
        if not user or not user.is_active:
            return None
        
        return user
        
    except Exception as e:
        logger.warning(f"Optional authentication failed: {e}")
        return None

async def verify_refresh_token(
    refresh_token: str
) -> tuple[User, RefreshToken]:
    """
    Dependency to verify refresh token and get associated user.
    
    Args:
        refresh_token: Refresh token string
        
    Returns:
        Tuple of (User, RefreshToken) if valid
        
    Raises:
        HTTPException: If token is invalid
    """
    # Verify token format and signature
    token_payload = jwt_service.verify_refresh_token(refresh_token)
    
    if not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    
    # Hash the token to find it in database
    token_hash = jwt_service.hash_token(refresh_token)
    
    # Find token in database
    token_doc = await RefreshToken.find_valid_token(token_hash)
    
    if not token_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found or expired",
        )
    
    # Get user
    user = await User.get(token_doc.user_id)
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account deactivated",
        )
    
    return user, token_doc

class RateLimiter:
    """
    Rate limiting dependency factory.
    Creates rate limiters for different endpoints and IP addresses.
    """
    
    def __init__(self, max_requests: int, window_seconds: int, scope: str = "global"):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
            scope: Scope for rate limiting (global, ip, user)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.scope = scope
    
    async def __call__(self, request: Request) -> None:
        """
        Check rate limit for the request.
        
        Args:
            request: FastAPI request object
            
        Raises:
            HTTPException: If rate limit exceeded
        """
        # Get client IP address
        client_ip = self._get_client_ip(request)
        
        # Create rate limit key
        if self.scope == "ip":
            key = f"rate_limit:ip:{client_ip}:{request.url.path}"
        elif self.scope == "global":
            key = f"rate_limit:global:{request.url.path}"
        else:
            key = f"rate_limit:{self.scope}:{client_ip}:{request.url.path}"
        
        # Check rate limit using Redis
        current_requests = await redis_service.increment_with_expiry(
            key, self.window_seconds
        )
        
        if current_requests > self.max_requests:
            # Calculate retry after time
            retry_after = self.window_seconds
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Rate limit exceeded",
                    "retry_after": retry_after,
                    "limit": self.max_requests,
                    "window": self.window_seconds
                }
            )
        
        # Add rate limit headers to response (will be added by middleware)
        request.state.rate_limit_remaining = self.max_requests - current_requests
        request.state.rate_limit_limit = self.max_requests
        request.state.rate_limit_reset = self.window_seconds
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address from request.
        Handles various proxy headers.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address
        """
        # Check for forwarded headers (common in production with reverse proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Get first IP in case of multiple
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"

# Pre-configured rate limiters for different endpoints

# General API rate limiting (60 requests per minute)
general_rate_limit = RateLimiter(
    max_requests=settings.rate_limit_per_minute,
    window_seconds=60,
    scope="ip"
)

# Strict rate limiting for authentication endpoints (10 requests per minute)
auth_rate_limit = RateLimiter(
    max_requests=10,
    window_seconds=60,
    scope="ip"
)

# Very strict rate limiting for OTP/email endpoints (5 requests per 10 minutes)
otp_rate_limit = RateLimiter(
    max_requests=5,
    window_seconds=600,
    scope="ip"
)

# Password reset rate limiting (3 requests per hour)
password_reset_rate_limit = RateLimiter(
    max_requests=3,
    window_seconds=3600,
    scope="ip"
)

async def get_request_info(request: Request) -> dict:
    """
    Extract useful information from request for logging and security.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dictionary with request information
    """
    return {
        "ip_address": RateLimiter._get_client_ip(RateLimiter(1, 1), request),
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "method": request.method,
        "url": str(request.url),
        "timestamp": datetime.now(UTC),
    }

async def check_user_role(required_roles: list[str]):
    """
    Dependency factory to check if user has required role.
    
    Args:
        required_roles: List of allowed roles
        
    Returns:
        Dependency function that checks user role
    """
    async def role_checker(current_user: User = Depends(get_current_verified_user)):
        if current_user.identity not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(required_roles)}",
            )
        return current_user
    
    return role_checker

# Role-specific dependencies
broker_only = check_user_role(["broker"])
builder_only = check_user_role(["builder"])
customer_only = check_user_role(["customer"])
broker_or_builder = check_user_role(["broker", "builder"])
admin_roles = check_user_role(["admin"])  # For future admin functionality