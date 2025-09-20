"""
Authentication controller containing all authentication business logic.
This handles user registration, login, email verification, password management, etc.
"""

from fastapi import HTTPException, status, Request
from app.models.user import User, UserRole
from app.models.otp import OTP, OTPType
from app.models.refresh_token import RefreshToken
from app.services.password_service import password_service
from app.services.jwt_service import jwt_service
from app.services.email_service import email_service
from app.connectors.redis_client import redis_service
from app.controllers.schemas import *
from app.core.config import settings
from typing import Optional, Tuple
from datetime import datetime, timedelta, UTC
from bson import ObjectId
import logging

# Set up logging
logger = logging.getLogger(__name__)

class AuthController:
    """
    Controller class for authentication operations.
    Contains all business logic for user authentication flows.
    """
    
    @staticmethod
    async def signup(
        signup_data: SignupRequest,
        request_info: dict
    ) -> Tuple[User, str]:
        """
        Handle user registration/signup process.
        
        Args:
            signup_data: User registration data
            request_info: Request metadata (IP, user agent, etc.)
            
        Returns:
            Tuple of (User object, OTP code)
            
        Raises:
            HTTPException: If registration fails
        """
        # Check if email already exists
        existing_user = await User.find_one({"email": signup_data.email})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address is already registered"
            )
        
        # Check if phone already exists
        existing_phone = await User.find_one({"phone": signup_data.phone})
        if existing_phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number is already registered"
            )
        
        # Validate password strength
        is_valid, password_errors = password_service.validate_password_strength(signup_data.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Password does not meet security requirements",
                    "errors": password_errors
                }
            )
        
        # Hash the password
        password_hash = password_service.hash_password(signup_data.password)
        
        # Create new user (email not verified yet)
        user = User(
            name=signup_data.name,
            phone=signup_data.phone,
            email=signup_data.email,
            password_hash=password_hash,
            identity=signup_data.identity,
            is_email_verified=False
        )
        
        # Save user to database
        await user.insert()
        
        # Generate and send OTP for email verification
        otp = await OTP.create_otp(
            email=signup_data.email,
            otp_type=OTPType.EMAIL_VERIFICATION,
            expire_minutes=settings.otp_expire_minutes,
            ip_address=request_info.get("ip_address")
        )
        
        # Send verification email
        email_sent = await email_service.send_otp_email(
            email=signup_data.email,
            name=signup_data.name,
            otp_code=otp.otp_code,
            purpose="verify your email address"
        )
        
        if not email_sent:
            # If email fails, still return success but log the error
            logger.error(f"Failed to send verification email to {signup_data.email}")
        
        logger.info(f"User registered: {signup_data.email} ({signup_data.identity})")
        
        return user, otp.otp_code
    
    @staticmethod
    async def verify_email(
        email: str,
        otp_code: str
    ) -> User:
        """
        Verify user's email address using OTP.
        
        Args:
            email: User's email address
            otp_code: 6-digit OTP code
            
        Returns:
            Verified user object
            
        Raises:
            HTTPException: If verification fails
        """
        # Find the OTP
        otp = await OTP.find_one({
            "email": email,
            "otp_type": OTPType.EMAIL_VERIFICATION,
            "is_used": False
        })
        
        if not otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending verification found for this email"
            )
        
        # Verify the OTP
        is_valid = await otp.verify_otp(otp_code)
        
        if not is_valid:
            if otp.attempts >= otp.max_attempts:
                detail = "Too many failed attempts. Please request a new verification code."
            elif otp.is_expired():
                detail = "Verification code has expired. Please request a new one."
            else:
                detail = "Invalid verification code"
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=detail
            )
        
        # Find and verify the user
        user = await User.find_one({"email": email})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Mark email as verified
        await user.verify_email()
        
        # Send welcome email
        await email_service.send_welcome_email(
            email=user.email,
            name=user.name,
            identity=user.identity
        )
        
        logger.info(f"Email verified: {email}")
        
        return user
    
    @staticmethod
    async def signin(
        signin_data: SigninRequest,
        request_info: dict
    ) -> Tuple[User, str, str]:
        """
        Handle user signin/login process.
        
        Args:
            signin_data: Login credentials
            request_info: Request metadata
            
        Returns:
            Tuple of (User, access_token, refresh_token)
            
        Raises:
            HTTPException: If login fails
        """
        # Find user by email
        user = await User.find_one({"email": signin_data.email})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if account is locked
        if user.is_account_locked():
            lock_time_remaining = user.locked_until - datetime.now(UTC)
            minutes_remaining = int(lock_time_remaining.total_seconds() / 60)
            
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account is locked due to multiple failed login attempts. Try again in {minutes_remaining} minutes."
            )
        
        # Verify password
        is_password_valid = password_service.verify_password(
            signin_data.password,
            user.password_hash
        )
        
        if not is_password_valid:
            # Increment failed login attempts
            await user.increment_failed_login()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if account is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated. Please contact support."
            )
        
        # Reset failed login attempts on successful login
        await user.reset_failed_login()
        
        # Create access token
        access_token = jwt_service.create_access_token(
            user_id=str(user.id),
            email=user.email,
            identity=user.identity
        )
        
        # Create refresh token
        refresh_token, token_hash, jti, expires_at = jwt_service.create_refresh_token(
            user_id=str(user.id)
        )
        
        # Store refresh token in database
        await RefreshToken.create_token(
            user_id=user.id,
            token_hash=token_hash,
            jti=jti,
            expires_at=expires_at,
            device_info=request_info.get("user_agent"),
            ip_address=request_info.get("ip_address"),
            user_agent=request_info.get("user_agent")
        )
        
        logger.info(f"User signed in: {user.email}")
        
        return user, access_token, refresh_token
    
    @staticmethod
    async def resend_otp(
        email: str,
        request_info: dict
    ) -> str:
        """
        Resend OTP for email verification.
        
        Args:
            email: User's email address
            request_info: Request metadata
            
        Returns:
            New OTP code
            
        Raises:
            HTTPException: If resend fails
        """
        # Find user
        user = await User.find_one({"email": email})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check if email is already verified
        if user.is_email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already verified"
            )
        
        # Check rate limiting for OTP generation
        recent_otp_count = await OTP.get_recent_otp_count(
            email=email,
            otp_type=OTPType.EMAIL_VERIFICATION,
            minutes=60  # Check last hour
        )
        
        if recent_otp_count >= 3:  # Max 3 OTPs per hour
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many OTP requests. Please wait before requesting another."
            )
        
        # Generate new OTP
        otp = await OTP.create_otp(
            email=email,
            otp_type=OTPType.EMAIL_VERIFICATION,
            expire_minutes=settings.otp_expire_minutes,
            ip_address=request_info.get("ip_address")
        )
        
        # Send verification email
        email_sent = await email_service.send_otp_email(
            email=email,
            name=user.name,
            otp_code=otp.otp_code,
            purpose="verify your email address"
        )
        
        if not email_sent:
            logger.error(f"Failed to resend verification email to {email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email"
            )
        
        logger.info(f"OTP resent to: {email}")
        
        return otp.otp_code
    
    @staticmethod
    async def refresh_token(
        refresh_token: str,
        request_info: dict
    ) -> Tuple[str, str]:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Current refresh token
            request_info: Request metadata
            
        Returns:
            Tuple of (new_access_token, new_refresh_token)
            
        Raises:
            HTTPException: If refresh fails
        """
        # Verify refresh token
        token_payload = jwt_service.verify_refresh_token(refresh_token)
        if not token_payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Hash token to find in database
        token_hash = jwt_service.hash_token(refresh_token)
        
        # Find token in database
        token_doc = await RefreshToken.find_valid_token(token_hash)
        if not token_doc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found or expired"
            )
        
        # Get user
        user = await User.get(token_doc.user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or account deactivated"
            )
        
        # Mark current token as used
        await token_doc.use_token()
        
        # Create new access token
        new_access_token = jwt_service.create_access_token(
            user_id=str(user.id),
            email=user.email,
            identity=user.identity
        )
        
        # Create new refresh token (token rotation for security)
        new_refresh_token, new_token_hash, new_jti, new_expires_at = jwt_service.create_refresh_token(
            user_id=str(user.id)
        )
        
        # Revoke old refresh token
        await token_doc.revoke("token_rotation")
        
        # Store new refresh token
        await RefreshToken.create_token(
            user_id=user.id,
            token_hash=new_token_hash,
            jti=new_jti,
            expires_at=new_expires_at,
            device_info=request_info.get("user_agent"),
            ip_address=request_info.get("ip_address"),
            user_agent=request_info.get("user_agent")
        )
        
        logger.info(f"Token refreshed for user: {user.email}")
        
        return new_access_token, new_refresh_token
    
    @staticmethod
    async def forgot_password(
        email: str,
        request_info: dict
    ) -> bool:
        """
        Handle forgot password request.
        
        Args:
            email: User's email address
            request_info: Request metadata
            
        Returns:
            True if email was sent (or if email doesn't exist for security)
            
        Raises:
            HTTPException: If request fails
        """
        # Always return success to prevent email enumeration attacks
        # But only send email if user actually exists
        
        user = await User.find_one({"email": email})
        
        if user and user.is_active:
            # Check rate limiting for password reset
            reset_count = await OTP.get_recent_otp_count(
                email=email,
                otp_type=OTPType.PASSWORD_RESET,
                minutes=60  # Check last hour
            )
            
            if reset_count >= 2:  # Max 2 password resets per hour
                # Still return success but don't send email
                logger.warning(f"Password reset rate limited for: {email}")
                return True
            
            # Generate password reset token (JWT with short expiry)
            reset_token = jwt_service.create_password_reset_token(
                user_id=str(user.id),
                email=user.email
            )
            
            # Store OTP record for tracking
            await OTP.create_otp(
                email=email,
                otp_type=OTPType.PASSWORD_RESET,
                expire_minutes=30,  # 30 minutes for password reset
                ip_address=request_info.get("ip_address")
            )
            
            # Send password reset email
            email_sent = await email_service.send_password_reset_email(
                email=user.email,
                name=user.name,
                reset_token=reset_token
            )
            
            if not email_sent:
                logger.error(f"Failed to send password reset email to {email}")
        
        # Always return True for security (don't reveal if email exists)
        return True
    
    @staticmethod
    async def reset_password(
        token: str,
        new_password: str
    ) -> User:
        """
        Reset password using reset token.
        
        Args:
            token: Password reset token
            new_password: New password
            
        Returns:
            User object
            
        Raises:
            HTTPException: If reset fails
        """
        # Verify reset token
        token_payload = jwt_service.verify_password_reset_token(token)
        if not token_payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Get user
        user_id = token_payload.get("sub")
        user = await User.get(user_id)
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Validate new password strength
        is_valid, password_errors = password_service.validate_password_strength(new_password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Password does not meet security requirements",
                    "errors": password_errors
                }
            )
        
        # Hash new password
        new_password_hash = password_service.hash_password(new_password)
        
        # Update user password
        user.password_hash = new_password_hash
        user.updated_at = datetime.now(UTC)
        
        # Reset failed login attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        
        await user.save()
        
        # Revoke all existing refresh tokens for security
        await RefreshToken.revoke_all_user_tokens(
            user_id=user.id,
            reason="password_reset"
        )
        
        # Mark password reset OTP as used
        reset_otp = await OTP.find_one({
            "email": user.email,
            "otp_type": OTPType.PASSWORD_RESET,
            "is_used": False
        })
        
        if reset_otp:
            reset_otp.is_used = True
            await reset_otp.save()
        
        logger.info(f"Password reset completed for: {user.email}")
        
        return user
    
    @staticmethod
    async def change_password(
        user: User,
        current_password: str,
        new_password: str
    ) -> User:
        """
        Change password for authenticated user.
        
        Args:
            user: Current authenticated user
            current_password: Current password
            new_password: New password
            
        Returns:
            Updated user object
            
        Raises:
            HTTPException: If password change fails
        """
        # Verify current password
        is_current_valid = password_service.verify_password(
            current_password,
            user.password_hash
        )
        
        if not is_current_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Validate new password strength
        is_valid, password_errors = password_service.validate_password_strength(new_password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Password does not meet security requirements",
                    "errors": password_errors
                }
            )
        
        # Check if new password is different from current
        if password_service.verify_password(new_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from current password"
            )
        
        # Hash new password
        new_password_hash = password_service.hash_password(new_password)
        
        # Update user password
        user.password_hash = new_password_hash
        user.updated_at = datetime.now(UTC)
        await user.save()
        
        # Revoke all existing refresh tokens except current session
        # (This forces re-login on all other devices)
        await RefreshToken.revoke_all_user_tokens(
            user_id=user.id,
            reason="password_change"
        )
        
        logger.info(f"Password changed for: {user.email}")
        
        return user
    
    @staticmethod
    async def logout(
        refresh_token: str
    ) -> bool:
        """
        Logout user by revoking refresh token.
        
        Args:
            refresh_token: Refresh token to revoke
            
        Returns:
            True if logout successful
            
        Raises:
            HTTPException: If logout fails
        """
        # Hash token to find in database
        token_hash = jwt_service.hash_token(refresh_token)
        
        # Find and revoke token
        token_doc = await RefreshToken.find_one({"token_hash": token_hash})
        
        if token_doc and token_doc.is_active:
            await token_doc.revoke("manual_logout")
            logger.info(f"User logged out: token revoked")
        
        return True
    
    @staticmethod
    async def logout_all_sessions(
        user: User
    ) -> int:
        """
        Logout user from all devices by revoking all refresh tokens.
        
        Args:
            user: User to logout from all sessions
            
        Returns:
            Number of sessions revoked
            
        Raises:
            HTTPException: If logout fails
        """
        # Get all active sessions
        active_sessions = await RefreshToken.get_user_sessions(user.id)
        
        # Revoke all tokens
        await RefreshToken.revoke_all_user_tokens(
            user_id=user.id,
            reason="logout_all_sessions"
        )
        
        logger.info(f"All sessions logged out for user: {user.email}")
        
        return len(active_sessions)
    
    @staticmethod
    async def get_user_sessions(
        user: User,
        current_jti: Optional[str] = None
    ) -> list:
        """
        Get all active sessions for a user.
        
        Args:
            user: User to get sessions for
            current_jti: JWT ID of current session to mark as current
            
        Returns:
            List of session information
        """
        # Get all active sessions
        sessions = await RefreshToken.get_user_sessions(user.id)
        
        # Convert to response format
        session_list = []
        for session in sessions:
            session_info = session.to_session_info()
            
            # Mark current session
            if current_jti and session.jti == current_jti:
                session_info["is_current"] = True
            
            session_list.append(session_info)
        
        return session_list
    
    @staticmethod
    async def validate_password_strength(
        password: str
    ) -> PasswordStrengthResponse:
        """
        Validate password strength and return detailed feedback.
        
        Args:
            password: Password to validate
            
        Returns:
            Password strength response
        """
        is_valid, errors = password_service.validate_password_strength(password)
        score, description = password_service.get_password_strength_score(password)
        
        return PasswordStrengthResponse(
            is_valid=is_valid,
            score=score,
            description=description,
            errors=errors
        )

# Create global instance
auth_controller = AuthController()