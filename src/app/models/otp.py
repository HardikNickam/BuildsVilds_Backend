"""
Complete OTP model with all required methods and fields.
"""
from beanie import Document, Indexed
from pydantic import EmailStr, Field
from datetime import datetime, timedelta, UTC
from typing import Optional
from enum import Enum
import secrets
import string


class OTPType(str, Enum):
    """OTP type enumeration."""
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    PHONE_VERIFICATION = "phone_verification"


class OTP(Document):
    """OTP document for email verification and other purposes."""
    
    email: Indexed(EmailStr)
    otp_code: str = Field(..., min_length=6, max_length=6)
    otp_type: OTPType = Field(default=OTPType.EMAIL_VERIFICATION)
    is_used: bool = Field(default=False)
    attempts: int = Field(default=0)
    max_attempts: int = Field(default=3)
    ip_address: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    class Settings:
        """Beanie document settings."""
        name = "otps"
        indexes = ["email", "expires_at", "otp_type"]

    @classmethod
    def generate_otp_code(cls) -> str:
        """Generate a 6-digit OTP code."""
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    @classmethod
    async def create_otp(
        cls, 
        email: str, 
        otp_type: OTPType = OTPType.EMAIL_VERIFICATION,
        expire_minutes: int = 10,
        ip_address: Optional[str] = None
    ):
        """Create a new OTP for an email."""
        # Remove any existing unused OTPs for this email and type
        existing_otps = await cls.find({
            "email": email, 
            "otp_type": otp_type,
            "is_used": False
        }).to_list()
        
        for otp in existing_otps:
            otp.is_used = True
            await otp.save()

        # Create new OTP - Both datetimes are timezone-aware
        otp_code = cls.generate_otp_code()
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=expire_minutes)

        otp = cls(
            email=email,
            otp_code=otp_code,
            otp_type=otp_type,
            expires_at=expires_at,
            ip_address=ip_address
        )
        await otp.insert()
        return otp

    def is_expired(self) -> bool:
        """Check if OTP is expired."""
        # Ensure both datetimes are timezone-aware
        current_time = datetime.now(UTC)
        expires_at = self.expires_at
        
        # If expires_at is timezone-naive, make it timezone-aware (UTC)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
            
        return current_time >= expires_at

    def is_valid(self) -> bool:
        """Check if OTP is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired()

    async def verify_otp(self, provided_code: str) -> bool:
        """
        Verify the provided OTP code.
        
        Args:
            provided_code: The code provided by the user
            
        Returns:
            True if verification successful, False otherwise
        """
        # Increment attempt count
        self.attempts += 1
        await self.save()
        
        # Check if too many attempts
        if self.attempts > self.max_attempts:
            return False
            
        # Check if expired
        if self.is_expired():
            return False
            
        # Check if already used
        if self.is_used:
            return False
            
        # Verify the code
        if self.otp_code == provided_code:
            self.is_used = True
            await self.save()
            return True
            
        return False

    async def use_otp(self):
        """Mark OTP as used."""
        self.is_used = True
        await self.save()

    @classmethod
    async def get_recent_otp_count(
        cls,
        email: str,
        otp_type: OTPType,
        minutes: int = 60
    ) -> int:
        """
        Get count of recent OTPs for rate limiting.
        
        Args:
            email: Email address
            otp_type: Type of OTP
            minutes: Time window in minutes
            
        Returns:
            Count of OTPs created in the time window
        """
        cutoff_time = datetime.now(UTC) - timedelta(minutes=minutes)
        
        count = await cls.find({
            "email": email,
            "otp_type": otp_type,
            "created_at": {"$gte": cutoff_time}
        }).count()
        
        return count