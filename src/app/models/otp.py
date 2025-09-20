"""
Phase 3: OTP model fixed for Python 3.12+ datetime.
"""

from beanie import Document, Indexed
from pydantic import EmailStr, Field
from datetime import datetime, timedelta, timezone
from typing import Optional
import secrets
import string

class OTP(Document):
    """OTP document for email verification."""
    
    email: Indexed(EmailStr)
    otp_code: str = Field(..., min_length=6, max_length=6)
    is_used: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))  # Fixed
    expires_at: datetime
    
    class Settings:
        """Beanie document settings."""
        name = "otps"
        indexes = ["email", "expires_at"]
    
    @classmethod
    def generate_otp_code(cls) -> str:
        """Generate a 6-digit OTP code."""
        return ''.join(secrets.choice(string.digits) for _ in range(6))
    
    @classmethod
    async def create_otp(cls, email: str, expire_minutes: int = 10):
        """Create a new OTP for an email."""
        # Remove any existing unused OTPs for this email
        existing_otps = await cls.find({"email": email, "is_used": False}).to_list()
        for otp in existing_otps:
            otp.is_used = True
            await otp.save()
        
        # Create new OTP - Fixed for Python 3.12+
        otp_code = cls.generate_otp_code()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=expire_minutes)
        
        otp = cls(
            email=email,
            otp_code=otp_code,
            expires_at=expires_at
        )
        await otp.insert()
        return otp
    
    def is_expired(self) -> bool:
        """Check if OTP is expired."""
        return datetime.now(timezone.utc) >= self.expires_at  # Fixed
    
    def is_valid(self) -> bool:
        """Check if OTP is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired()
    
    async def use_otp(self):
        """Mark OTP as used."""
        self.is_used = True
        await self.save()