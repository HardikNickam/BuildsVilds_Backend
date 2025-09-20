"""
Refresh token document model for secure session management.
This stores refresh tokens in the database for token rotation and security.
"""

from beanie import Document, Indexed
from pydantic import Field
from typing import Optional
from datetime import datetime, timedelta, UTC
from bson import ObjectId

class RefreshToken(Document):
    """
    Refresh token document stored in MongoDB.
    Used for secure token rotation and session management.
    """
    
    # Token information
    user_id: Indexed(ObjectId)  # Reference to the user (indexed for fast lookups)
    token_hash: Indexed(str, unique=True)  # Hashed refresh token (unique)
    jti: Indexed(str, unique=True)  # JWT ID - unique identifier for this token
    
    # Token metadata
    device_info: Optional[str] = None  # Device/browser information
    ip_address: Optional[str] = None  # IP address where token was created
    user_agent: Optional[str] = None  # User agent string
    
    # Token lifecycle
    is_active: bool = Field(default=True)  # Token active status
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime  # When the token expires
    last_used_at: Optional[datetime] = None  # When token was last used for refresh
    
    # Security tracking
    revoked_at: Optional[datetime] = None  # When token was revoked
    revoked_reason: Optional[str] = None  # Why token was revoked
    
    class Settings:
        """Beanie document settings."""
        name = "refresh_tokens"
        indexes = [
            "user_id",  # Find tokens by user
            "token_hash",  # Fast token lookups
            "jti",  # JWT ID lookups
            "expires_at",  # Clean up expired tokens
            "created_at",  # Sort by creation date
        ]
    
    @classmethod
    async def create_token(
        cls,
        user_id: ObjectId,
        token_hash: str,
        jti: str,
        expires_at: datetime,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """
        Create a new refresh token document.
        
        Args:
            user_id: User's ObjectId
            token_hash: Hashed refresh token
            jti: JWT ID
            expires_at: Expiration datetime
            device_info: Device information
            ip_address: Client IP address
            user_agent: User agent string
            
        Returns:
            Created RefreshToken document
        """
        token = cls(
            user_id=user_id,
            token_hash=token_hash,
            jti=jti,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await token.insert()
        return token
    
    async def revoke(self, reason: str = "manual"):
        """
        Revoke this refresh token.
        
        Args:
            reason: Reason for revocation
        """
        self.is_active = False
        self.revoked_at = datetime.now(UTC)
        self.revoked_reason = reason
        await self.save()
    
    async def use_token(self):
        """
        Mark token as used (update last_used_at).
        Called when token is used to refresh access token.
        """
        self.last_used_at = datetime.now(UTC)
        await self.save()
    
    def is_expired(self) -> bool:
        """
        Check if token is expired.
        
        Returns:
            True if expired, False otherwise
        """
        return datetime.now(UTC) >= self.expires_at
    
    def is_valid(self) -> bool:
        """
        Check if token is valid (active and not expired).
        
        Returns:
            True if valid, False otherwise
        """
        return self.is_active and not self.is_expired()
    
    @classmethod
    async def find_valid_token(cls, token_hash: str):
        """
        Find a valid refresh token by hash.
        
        Args:
            token_hash: Hashed token to find
            
        Returns:
            RefreshToken document if found and valid, None otherwise
        """
        token = await cls.find_one({"token_hash": token_hash})
        
        if not token or not token.is_valid():
            return None
            
        return token
    
    @classmethod
    async def revoke_all_user_tokens(cls, user_id: ObjectId, reason: str = "logout_all"):
        """
        Revoke all active tokens for a user.
        Used for "logout from all devices" functionality.
        
        Args:
            user_id: User's ObjectId
            reason: Reason for revocation
        """
        # Find all active tokens for the user
        active_tokens = await cls.find({"user_id": user_id, "is_active": True}).to_list()
        
        # Revoke each token
        for token in active_tokens:
            await token.revoke(reason)
    
    @classmethod
    async def cleanup_expired_tokens(cls):
        """
        Remove expired tokens from database.
        This should be run periodically as a cleanup job.
        """
        now = datetime.now(UTC)
        
        # Delete all expired tokens
        result = await cls.find({"expires_at": {"$lt": now}}).delete()
        
        return result.deleted_count if result else 0
    
    @classmethod
    async def get_user_sessions(cls, user_id: ObjectId):
        """
        Get all active sessions for a user.
        Used to show user their active sessions.
        
        Args:
            user_id: User's ObjectId
            
        Returns:
            List of active token documents
        """
        return await cls.find({
            "user_id": user_id,
            "is_active": True,
            "expires_at": {"$gt": datetime.now(UTC)}
        }).sort("-created_at").to_list()
    
    def to_session_info(self) -> dict:
        """
        Convert token to session information for user display.
        
        Returns:
            Dictionary with session information
        """
        return {
            "id": str(self.id),
            "device_info": self.device_info or "Unknown Device",
            "ip_address": self.ip_address,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "expires_at": self.expires_at,
            "is_current": False  # This should be set by the calling code
        }