"""
Phase 3: User model fixed for Python 3.12+ datetime.
"""

from beanie import Document, Indexed
from pydantic import EmailStr, Field
from datetime import datetime, timezone
from typing import Optional

class User(Document):
    """User document for MongoDB."""
    
    # Basic user information
    name: str = Field(..., min_length=2, max_length=100)
    phone: str = Field(..., min_length=10, max_length=15)
    email: Indexed(EmailStr, unique=True)
    password_hash: str
    identity: str  # broker, builder, customer
    
    # Verification status
    is_email_verified: bool = Field(default=False)
    
    # Timestamps - Fixed for Python 3.12+
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        """Beanie document settings."""
        name = "users"
        indexes = ["email"]
    
    def __repr__(self):
        return f"<User {self.email} ({self.identity})>"
    
    async def mark_email_verified(self):
        """Mark email as verified."""
        self.is_email_verified = True
        self.updated_at = datetime.now(timezone.utc)  # Fixed for Python 3.12+
        await self.save()