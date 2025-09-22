"""
Complete User model with all required methods and fields.
"""
from beanie import Document, Indexed
from pydantic import EmailStr, Field
from datetime import datetime, timedelta, UTC
from typing import Optional
from enum import Enum


class UserRole(str, Enum):
    """User role enumeration."""
    BROKER = "broker"
    BUILDER = "builder"
    CUSTOMER = "customer"


class User(Document):
    """User document for MongoDB."""
    
    # Basic user information
    name: str = Field(..., min_length=2, max_length=100)
    phone: str = Field(..., min_length=10, max_length=15)
    email: Indexed(EmailStr, unique=True)
    password_hash: str
    identity: str  # broker, builder, customer
    
    # Account status
    is_active: bool = Field(default=True)
    is_email_verified: bool = Field(default=False)
    
    # Security fields
    failed_login_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = None
    
    # Timestamps - Fixed for Python 3.12+
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    class Settings:
        """Beanie document settings."""
        name = "users"
        indexes = ["email"]

    def __repr__(self):
        return f"<User {self.email} ({self.identity})>"

    async def mark_email_verified(self):
        """Mark email as verified."""
        self.is_email_verified = True
        self.updated_at = datetime.now(UTC)
        await self.save()

    async def verify_email(self):
        """Verify email - alias for mark_email_verified for compatibility."""
        await self.mark_email_verified()

    def is_account_locked(self) -> bool:
        """Check if account is currently locked due to failed login attempts."""
        if not self.locked_until:
            return False
        return datetime.now(UTC) < self.locked_until

    async def increment_failed_login(self):
        """Increment failed login attempts and lock account if necessary."""
        self.failed_login_attempts += 1
        self.updated_at = datetime.now(UTC)
        
        # Lock account after 5 failed attempts for 30 minutes
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.now(UTC) + timedelta(minutes=30)
        
        await self.save()

    async def reset_failed_login(self):
        """Reset failed login attempts and unlock account."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.updated_at = datetime.now(UTC)
        await self.save()

    async def deactivate_account(self, reason: Optional[str] = None):
        """Deactivate user account."""
        self.is_active = False
        self.updated_at = datetime.now(UTC)
        await self.save()

    async def activate_account(self):
        """Activate user account."""
        self.is_active = True
        self.updated_at = datetime.now(UTC)
        await self.save()

    async def update_last_activity(self):
        """Update the user's last activity timestamp."""
        self.updated_at = datetime.now(UTC)
        await self.save()

    def to_dict(self, exclude_sensitive: bool = True) -> dict:
        """
        Convert user to dictionary representation.
        
        Args:
            exclude_sensitive: Whether to exclude sensitive fields like password_hash
            
        Returns:
            Dictionary representation of user
        """
        user_dict = {
            "id": str(self.id),
            "name": self.name,
            "phone": self.phone,
            "email": self.email,
            "identity": self.identity,
            "is_active": self.is_active,
            "is_email_verified": self.is_email_verified,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
        
        if not exclude_sensitive:
            user_dict.update({
                "password_hash": self.password_hash,
                "failed_login_attempts": self.failed_login_attempts,
                "locked_until": self.locked_until
            })
        
        return user_dict