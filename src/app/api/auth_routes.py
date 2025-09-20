"""
Phase 3: Authentication routes with JWT tokens and bcrypt password security.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr
from app.models.user import User
from app.models.otp import OTP
from app.services.jwt_service import jwt_service
from app.services.password_service import password_service
from app.utils.auth_middleware import get_current_user
from typing import Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Request schemas
class SignupRequest(BaseModel):
    name: str
    phone: str
    email: EmailStr
    password: str
    identity: str

class SigninRequest(BaseModel):
    email: EmailStr
    password: str

class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp_code: str

# Response schemas
class MessageResponse(BaseModel):
    message: str
    success: bool = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds

class AuthResponse(BaseModel):
    message: str
    user: dict
    tokens: TokenResponse
    success: bool = True

class UserResponse(BaseModel):
    user_id: str
    name: str
    email: str
    identity: str
    is_email_verified: bool

@router.post("/signup", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def signup(signup_data: SignupRequest):
    """Register new user with bcrypt password hashing and validation."""
    try:
        # Check if email already exists
        existing_user = await User.find_one({"email": signup_data.email})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address is already registered"
            )
        
        # Validate identity
        if signup_data.identity not in ["broker", "builder", "customer"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Identity must be broker, builder, or customer"
            )
        
        # Validate password strength
        is_valid, errors = password_service.validate_password_strength(signup_data.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Password does not meet requirements", "errors": errors}
            )
        
        # Hash password with bcrypt
        password_hash = password_service.hash_password(signup_data.password)
        
        # Create user
        user = User(
            name=signup_data.name,
            phone=signup_data.phone,
            email=signup_data.email,
            password_hash=password_hash,
            identity=signup_data.identity,
            is_email_verified=False
        )
        
        await user.insert()
        
        # Create OTP
        otp = await OTP.create_otp(email=signup_data.email)
        
        logger.info(f"✅ User registered with bcrypt: {signup_data.email} with OTP: {otp.otp_code}")
        
        return MessageResponse(
            message=f"Account created with secure password! OTP: {otp.otp_code} (expires in 10 minutes)",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during registration"
        )

@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(verify_data: VerifyEmailRequest):
    """Verify email using OTP."""
    try:
        # Find user
        user = await User.find_one({"email": verify_data.email})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Find valid OTP
        otp = await OTP.find_one({
            "email": verify_data.email,
            "otp_code": verify_data.otp_code,
            "is_used": False
        })
        
        if not otp or not otp.is_valid():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code"
            )
        
        # Mark email as verified
        await user.mark_email_verified()
        
        # Mark OTP as used
        await otp.use_otp()
        
        logger.info(f"✅ Email verified: {verify_data.email}")
        
        return MessageResponse(
            message="Email verified successfully! You can now sign in and receive JWT tokens.",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Email verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during email verification"
        )

@router.post("/signin", response_model=AuthResponse)
async def signin(signin_data: SigninRequest):
    """Sign in user and return JWT token."""
    try:
        # Find user
        user = await User.find_one({"email": signin_data.email})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Verify password with bcrypt
        if not password_service.verify_password(signin_data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if email is verified
        if not user.is_email_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please verify your email address before signing in"
            )
        
        # Create JWT token
        access_token = jwt_service.create_access_token(
            user_id=str(user.id),
            email=user.email,
            identity=user.identity
        )
        
        logger.info(f"✅ User signed in with JWT: {user.email}")
        
        return AuthResponse(
            message="Sign in successful! JWT token generated.",
            user={
                "user_id": str(user.id),
                "name": user.name,
                "email": user.email,
                "identity": user.identity,
                "is_email_verified": user.is_email_verified
            },
            tokens=TokenResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=3600  # 1 hour
            ),
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Signin error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during sign in"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    🔒 PROTECTED ENDPOINT - Get current authenticated user information.
    Requires JWT token in Authorization header: Bearer <token>
    """
    return UserResponse(
        user_id=str(current_user.id),
        name=current_user.name,
        email=current_user.email,
        identity=current_user.identity,
        is_email_verified=current_user.is_email_verified
    )

@router.post("/test-protected", response_model=MessageResponse)
async def test_protected_endpoint(current_user: User = Depends(get_current_user)):
    """
    🔒 PROTECTED ENDPOINT - Test JWT authentication.
    Use this to verify JWT tokens are working correctly.
    """
    return MessageResponse(
        message=f"🎉 Hello {current_user.name}! JWT authentication is working. Your role: {current_user.identity}",
        success=True
    )

@router.get("/users")
async def list_users():
    """Debug endpoint to see all users."""
    users = await User.find_all().to_list()
    return {
        "total_users": len(users),
        "users": [
            {
                "email": user.email,
                "name": user.name,
                "identity": user.identity,
                "is_verified": user.is_email_verified,
                "created_at": user.created_at
            }
            for user in users
        ]
    }

@router.delete("/reset-data")
async def reset_data():
    """Reset all data for testing."""
    await User.delete_all()
    await OTP.delete_all()
    return {"message": "All data cleared", "success": True}