import os
import secrets
import hashlib
from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any, Tuple
from jose import jwt, JWTError


class JWTService:
    """JWT service for authentication tokens."""
    
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY", "fallback-secret-key")
        self.algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.access_token_expire_minutes = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))
        self.refresh_token_expire_days = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 30))
        self.password_reset_expire_minutes = int(os.getenv("JWT_PASSWORD_RESET_EXPIRE_MINUTES", 30))
    
    def create_access_token(self, user_id: str, email: str, identity: str) -> str:
        """Create JWT access token."""
        now = datetime.now(UTC)
        expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        payload = {
            "sub": user_id,  # Subject (user ID)
            "email": email,
            "identity": identity,
            "iat": now,  # Issued at
            "exp": expire,  # Expires at
            "jti": secrets.token_urlsafe(16),  # JWT ID
            "type": "access"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user_id: str) -> Tuple[str, str, str, datetime]:
        """
        Create refresh token and return token, hash, jti, and expiration.
        
        Args:
            user_id: User's ID
            
        Returns:
            Tuple of (token, token_hash, jti, expires_at)
        """
        now = datetime.now(UTC)
        expire = now + timedelta(days=self.refresh_token_expire_days)
        jti = secrets.token_urlsafe(32)
        
        payload = {
            "sub": user_id,
            "iat": now,
            "exp": expire,
            "jti": jti,
            "type": "refresh"
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        token_hash = self.hash_token(token)
        
        return token, token_hash, jti, expire
    
    def create_password_reset_token(self, user_id: str, email: str) -> str:
        """Create password reset token."""
        now = datetime.now(UTC)
        expire = now + timedelta(minutes=self.password_reset_expire_minutes)
        
        payload = {
            "sub": user_id,
            "email": email,
            "iat": now,
            "exp": expire,
            "jti": secrets.token_urlsafe(16),
            "type": "password_reset"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT access token and return payload."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if it's an access token
            if payload.get("type") != "access":
                return None
                
            # Check required fields
            if not all(key in payload for key in ["sub", "email", "identity"]):
                return None
                
            return payload
            
        except JWTError:
            return None
        except Exception:
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify refresh token and return payload."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if it's a refresh token
            if payload.get("type") != "refresh":
                return None
                
            # Check required fields
            if not all(key in payload for key in ["sub", "jti"]):
                return None
                
            return payload
            
        except JWTError:
            return None
        except Exception:
            return None
    
    def verify_password_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify password reset token and return payload."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if it's a password reset token
            if payload.get("type") != "password_reset":
                return None
                
            # Check required fields
            if not all(key in payload for key in ["sub", "email"]):
                return None
                
            return payload
            
        except JWTError:
            return None
        except Exception:
            return None
    
    def get_user_from_token(self, token: str) -> Optional[Dict[str, str]]:
        """Extract user info from access token."""
        payload = self.verify_access_token(token)
        if not payload:
            return None
            
        return {
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
            "identity": payload.get("identity")
        }
    
    def hash_token(self, token: str) -> str:
        """Create a hash of the token for secure storage."""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def extract_jti_from_token(self, token: str) -> Optional[str]:
        """Extract JTI from token without full verification."""
        try:
            # Decode without verification to get JTI
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload.get("jti")
        except:
            return None


# Global JWT service instance
jwt_service = JWTService()