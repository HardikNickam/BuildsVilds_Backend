"""
Pydantic schemas for request/response validation in authentication endpoints.
These schemas define the structure of data sent to and from the API.
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from app.models.user import UserRole

# Request Schemas (Data coming from client)

class SignupRequest(BaseModel):
    """Schema for user signup request."""
    name: str = Field(..., min_length=2, max_length=100, description="User's full name")
    phone: str = Field(..., min_length=10, max_length=15, description="Phone number")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password")
    identity: UserRole = Field(..., description="User role: broker, builder, or customer")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate name contains only letters, spaces, and common punctuation."""
        if not v.replace(' ', '').replace('-', '').replace('.', '').replace("'", '').isalpha():
            raise ValueError('Name must contain only letters, spaces, hyphens, periods, and apostrophes')
        return v.strip()
    
    @validator('phone')
    def validate_phone(cls, v):
        """Basic phone number validation."""
        # Remove common phone number formatting
        cleaned = v.replace('+', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
        if not cleaned.isdigit():
            raise ValueError('Phone number must contain only digits and common formatting characters')
        return cleaned

class SigninRequest(BaseModel):
    """Schema for user signin request."""
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Password")

class VerifyEmailRequest(BaseModel):
    """Schema for email verification request."""
    email: EmailStr = Field(..., description="Email address")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")
    
    @validator('otp_code')
    def validate_otp_code(cls, v):
        """Validate OTP code is 6 digits."""
        if not v.isdigit():
            raise ValueError('OTP code must contain only digits')
        return v

class ResendOtpRequest(BaseModel):
    """Schema for resend OTP request."""
    email: EmailStr = Field(..., description="Email address")

class RefreshTokenRequest(BaseModel):
    """Schema for refresh token request."""
    refresh_token: str = Field(..., description="Refresh token")

class ForgotPasswordRequest(BaseModel):
    """Schema for forgot password request."""
    email: EmailStr = Field(..., description="Email address")

class ResetPasswordRequest(BaseModel):
    """Schema for password reset request."""
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")

class ChangePasswordRequest(BaseModel):
    """Schema for password change request (authenticated user)."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")

# Response Schemas (Data sent to client)

class UserResponse(BaseModel):
    """Schema for user data in API responses."""
    id: str = Field(..., description="User ID")
    name: str = Field(..., description="User's full name")
    phone: str = Field(..., description="Phone number")
    email: str = Field(..., description="Email address")
    identity: UserRole = Field(..., description="User role")
    is_email_verified: bool = Field(..., description="Email verification status")
    is_active: bool = Field(..., description="Account active status")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    avatar_url: Optional[str] = Field(None, description="Profile picture URL")
    bio: Optional[str] = Field(None, description="User biography")
    location: Optional[str] = Field(None, description="User location")

class TokenResponse(BaseModel):
    """Schema for authentication token response."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiry in seconds")

class AuthResponse(BaseModel):
    """Schema for authentication response (signin/signup)."""
    user: UserResponse = Field(..., description="User information")
    tokens: TokenResponse = Field(..., description="Authentication tokens")

class MessageResponse(BaseModel):
    """Schema for simple message responses."""
    message: str = Field(..., description="Response message")
    success: bool = Field(default=True, description="Operation success status")

class ErrorResponse(BaseModel):
    """Schema for error responses."""
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code for client handling")
    errors: Optional[List[str]] = Field(None, description="List of validation errors")

class PasswordStrengthResponse(BaseModel):
    """Schema for password strength validation response."""
    is_valid: bool = Field(..., description="Whether password meets requirements")
    score: int = Field(..., description="Password strength score (0-100)")
    description: str = Field(..., description="Password strength description")
    errors: List[str] = Field(..., description="List of password requirement violations")

class SessionInfo(BaseModel):
    """Schema for user session information."""
    id: str = Field(..., description="Session ID")
    device_info: str = Field(..., description="Device information")
    ip_address: Optional[str] = Field(None, description="IP address")
    created_at: datetime = Field(..., description="Session creation time")
    last_used_at: Optional[datetime] = Field(None, description="Last activity time")
    expires_at: datetime = Field(..., description="Session expiry time")
    is_current: bool = Field(..., description="Whether this is the current session")

class UserSessionsResponse(BaseModel):
    """Schema for user sessions list response."""
    sessions: List[SessionInfo] = Field(..., description="List of active sessions")
    total_sessions: int = Field(..., description="Total number of active sessions")

class OtpStatusResponse(BaseModel):
    """Schema for OTP status response."""
    email: str = Field(..., description="Email address")
    otp_sent: bool = Field(..., description="Whether OTP was sent successfully")
    expires_in_minutes: int = Field(..., description="OTP expiry time in minutes")
    can_resend_after: Optional[int] = Field(None, description="Seconds until can resend OTP")

# Health check schema
class HealthCheckResponse(BaseModel):
    """Schema for health check endpoint."""
    status: str = Field(default="healthy", description="Service status")
    timestamp: datetime = Field(
    default_factory=lambda: datetime.now(UTC),
    description="Health check timestamp"
    )   
    database: str = Field(..., description="Database connection status")
    redis: str = Field(..., description="Redis connection status")
    email: str = Field(..., description="Email service status")

# Rate limiting schema
class RateLimitResponse(BaseModel):
    """Schema for rate limit exceeded response."""
    detail: str = Field(default="Rate limit exceeded", description="Error message")
    retry_after: int = Field(..., description="Seconds until rate limit resets")
    limit: int = Field(..., description="Rate limit threshold")
    window: int = Field(..., description="Rate limit window in seconds")

# Validation schemas
class EmailValidationResponse(BaseModel):
    """Schema for email validation response."""
    email: str = Field(..., description="Email address")
    is_valid: bool = Field(..., description="Whether email format is valid")
    is_available: bool = Field(..., description="Whether email is available for registration")

class PhoneValidationResponse(BaseModel):
    """Schema for phone validation response."""
    phone: str = Field(..., description="Phone number")
    is_valid: bool = Field(..., description="Whether phone format is valid")
    formatted: str = Field(..., description="Formatted phone number")
    is_available: bool = Field(..., description="Whether phone is available for registration")