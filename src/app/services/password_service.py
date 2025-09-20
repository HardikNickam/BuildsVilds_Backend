"""
Phase 3: Secure password service with bcrypt hashing.
"""

from passlib.context import CryptContext
from typing import Tuple, List
import re

# Create password context with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class PasswordService:
    """Service for secure password operations."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with bcrypt."""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            return False
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
        """Validate password strength."""
        errors = []
        
        # Length check
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        # Uppercase letter
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Lowercase letter  
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Digit
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one number")
        
        # Special character
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors

# Global password service instance
password_service = PasswordService()