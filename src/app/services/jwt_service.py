"""
Phase 3: JWT service for creating and verifying tokens.
Fixed for Python 3.12+ - using timezone-aware datetime.
"""

from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import os
from typing import Optional, Dict, Any
import secrets

class JWTService:
    """JWT service for authentication tokens."""
    
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY", "fallback-secret-key")
        self.algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.access_token_expire_minutes = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))
    
    def create_access_token(self, user_id: str, email: str, identity: str) -> str:
        """Create JWT access token."""
        now = datetime.now(timezone.utc)  # Python 3.12+ compatible
        expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        payload = {
            "sub": user_id,  # Subject (user ID)
            "email": email,
            "identity": identity,
            "iat": now,  # Issued at
            "exp": expire,  # Expires at
            "jti": secrets.token_urlsafe(16),  # JWT ID
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT access token and return payload."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check required fields
            if not all(key in payload for key in ["sub", "email", "identity"]):
                return None
            
            return payload
            
        except JWTError:
            return None
        except Exception:
            return None
    
    def get_user_from_token(self, token: str) -> Optional[Dict[str, str]]:
        """Extract user info from token."""
        payload = self.verify_access_token(token)
        if not payload:
            return None
        
        return {
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
            "identity": payload.get("identity")
        }

# Global JWT service instance
jwt_service = JWTService()